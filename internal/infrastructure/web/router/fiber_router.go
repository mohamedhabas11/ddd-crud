// internal/infrastructure/web/router/fiber_router.go
package router

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"

	"github.com/gofiber/adaptor/v2" // Use v2 for remaining http.HandlerFunc handlers

	"github.com/mohamedhabas11/ddd-crud/internal/infrastructure/security"
	"github.com/mohamedhabas11/ddd-crud/internal/infrastructure/web/handler"
)

// FiberRouterConfig defines the configuration for the Fiber application.
type FiberRouterConfig struct {
	AppName      string
	BodyLimit    int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// NewFiberRouter creates and configures a new Fiber application instance.
func NewFiberRouter(
	cfg FiberRouterConfig,
	userHandler *handler.UserHandler,
	jwtService *security.JWTService,
	appLogger *log.Logger,
	// Add other handlers here if needed
) *fiber.App {

	appLogger.Println("INFO: Creating Fiber application...")

	// Configure Fiber
	fiberConfig := fiber.Config{
		AppName:               cfg.AppName,
		BodyLimit:             cfg.BodyLimit * 1024 * 1024, // Convert MB to bytes
		ReadTimeout:           cfg.ReadTimeout,
		WriteTimeout:          cfg.WriteTimeout,
		DisableStartupMessage: true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			message := "Internal Server Error"
			var e *fiber.Error
			if errors.As(err, &e) {
				code = e.Code
				message = e.Message
			} else {
				appLogger.Printf("ERROR: Unhandled Fiber error on path %s: %v", c.Path(), err)
			}
			// Use the Fiber helper function for consistency
			return handler.RespondWithErrorFiber(c, appLogger, message, code, err)
		},
	}
	app := fiber.New(fiberConfig)

	// --- Global Middleware ---
	appLogger.Println("INFO: Registering Fiber middleware...")
	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(logger.New(logger.Config{
		Format:     "[${time}] ${ip} ${status} - ${latency} ${method} ${path} ${queryParams}\n", // Added queryParams
		TimeFormat: "2006-01-02 15:04:05",
		Output:     appLogger.Writer(),
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*", // Consider restricting this in production
		AllowMethods: "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))

	// --- Middleware Definitions ---

	// idParamMiddleware extracts the user ID from the route parameter ":id"
	// and inserts it into Fiber Locals.
	idParamMiddleware := func(c *fiber.Ctx) error {
		idStr := c.Params("id")
		if idStr == "" {
			appLogger.Println("WARN: ID parameter missing in request to", c.Path())
			return handler.RespondWithErrorFiber(c, appLogger, "Missing user ID parameter", fiber.StatusBadRequest, nil)
		}

		id, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			appLogger.Printf("WARN: Invalid ID parameter format '%s' in request to %s: %v", idStr, c.Path(), err)
			return handler.RespondWithErrorFiber(c, appLogger, "Invalid user ID format", fiber.StatusBadRequest, err)
		}

		// --- Store in Locals ---
		// Use the constant string value as the key for Locals
		c.Locals(string(handler.ContextKeyTargetUserID), uint(id))
		// --- End Store in Locals ---

		appLogger.Printf("DEBUG: idParamMiddleware - Set TargetUserID %d in Locals for path %s", id, c.Path())
		return c.Next()
	}

	// authMiddleware validates the JWT token from the Authorization header
	// and stores the resulting claims in Fiber Locals.
	authMiddleware := func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			appLogger.Println("WARN: Auth middleware - Missing Authorization header")
			return handler.RespondWithErrorFiber(c, appLogger, "Missing authorization header", fiber.StatusUnauthorized, nil)
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") { // Use EqualFold for case-insensitive comparison
			appLogger.Println("WARN: Auth middleware - Malformed Authorization header")
			return handler.RespondWithErrorFiber(c, appLogger, "Malformed authorization header", fiber.StatusUnauthorized, nil)
		}

		tokenString := parts[1]
		claims, err := jwtService.ValidateToken(tokenString)
		if err != nil {
			appLogger.Printf("WARN: Auth middleware - Invalid token: %v", err)
			status := fiber.StatusUnauthorized
			message := "Invalid or expired token"
			if errors.Is(err, security.ErrTokenExpired) {
				message = "Token has expired"
			} else if errors.Is(err, security.ErrTokenInvalid) {
				message = "Token is invalid"
			}
			return handler.RespondWithErrorFiber(c, appLogger, message, status, err)
		}

		// --- Store Claims in Locals ---
		// Use the constant string value as the key for Locals
		c.Locals(string(handler.ContextKeyAuthClaims), claims)
		// --- End Store Claims in Locals ---

		appLogger.Printf("DEBUG: Auth middleware - Set Claims (UserID: %d, Role: %s) in Locals for path %s", claims.UserID, claims.Role.String(), c.Path())
		return c.Next()
	}

	// --- Routes ---
	apiGroup := app.Group("/api/v1")
	apiGroup.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(http.StatusOK).JSON(fiber.Map{"status": "ok"})
	})

	// User Routes
	userGroup := apiGroup.Group("/users")
	if userHandler != nil {
		appLogger.Println("INFO: Registering User routes...")

		// Public routes (still using adaptor as they are http.HandlerFunc)
		userGroup.Post("/", adaptor.HTTPHandlerFunc(userHandler.HandleCreateUser))
		userGroup.Post("/login", adaptor.HTTPHandlerFunc(userHandler.HandleLogin))

		// Protected Routes (using direct Fiber handlers now)
		// Middleware applied in order: Auth -> [ID Param] -> Handler
		userGroup.Get("/", authMiddleware, userHandler.HandleListUsers) // No ID param needed
		userGroup.Get("/:id", authMiddleware, idParamMiddleware, userHandler.HandleGetUserByID)
		userGroup.Put("/:id", authMiddleware, idParamMiddleware, userHandler.HandleUpdateUserDetails)
		userGroup.Patch("/:id/password", authMiddleware, idParamMiddleware, userHandler.HandleChangePassword)
		userGroup.Patch("/:id/activate", authMiddleware, idParamMiddleware, userHandler.HandleActivateUser)     // Admin only
		userGroup.Patch("/:id/deactivate", authMiddleware, idParamMiddleware, userHandler.HandleDeactivateUser) // Admin only
		userGroup.Delete("/:id", authMiddleware, idParamMiddleware, userHandler.HandleDeleteUser)
	}

	appLogger.Println("INFO: Fiber application configured.")
	return app
}
