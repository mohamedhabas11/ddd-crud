// internal/infrastructure/web/router/fiber_router.go
package router

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger" // Fiber's request logger
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
// CHANGE the appLogger parameter type:
func NewFiberRouter(
	cfg FiberRouterConfig,
	userHandler *handler.UserHandler,
	jwtService *security.JWTService,
	appLogger *slog.Logger,
	// Add other handlers here if needed
) *fiber.App {

	// Use slog:
	appLogger.Info("Creating Fiber application...")

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
				// Log unexpected errors using slog
				appLogger.Error("Unhandled Fiber error", "path", c.Path(), "error", err)
			}
			// Use the Fiber helper function (which now accepts slog.Logger)
			// Log the response error details within RespondWithErrorFiber
			return handler.RespondWithErrorFiber(c, appLogger, message, code, err)
		},
	}
	app := fiber.New(fiberConfig)

	// --- Global Middleware ---
	appLogger.Info("Registering Fiber middleware...")
	app.Use(recover.New()) // Consider configuring recover to use slog if needed
	app.Use(requestid.New())

	// Configure Fiber's request logger
	// NOTE: This logs requests separately from your application's slog logs.
	// Pass the desired output writer directly (e.g., os.Stdout if that's where slog writes)
	var logOutput io.Writer = os.Stdout // Or os.Stderr, or a file writer
	app.Use(logger.New(logger.Config{
		Format:     "[${time}] ${ip} ${status} - ${latency} ${method} ${path} ${queryParams}\n",
		TimeFormat: "2006-01-02 15:04:05",
		Output:     logOutput, // Use the io.Writer
	}))

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*", // Consider restricting this in production
		AllowMethods: "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))

	// --- Middleware Definitions ---

	// idParamMiddleware extracts the user ID from the route parameter ":id"
	// and inserts it into Fiber Locals. Uses slog for logging.
	idParamMiddleware := func(c *fiber.Ctx) error {
		idStr := c.Params("id")
		path := c.Path() // Get path once

		if idStr == "" {
			// Use slog Warn
			appLogger.Warn("ID parameter missing in request", "path", path)
			return handler.RespondWithErrorFiber(c, appLogger, "Missing user ID parameter", fiber.StatusBadRequest, nil)
		}

		id, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			// Use slog Warn
			appLogger.Warn("Invalid ID parameter format", "id_param", idStr, "path", path, "error", err)
			return handler.RespondWithErrorFiber(c, appLogger, "Invalid user ID format", fiber.StatusBadRequest, err)
		}

		targetUserID := uint(id)
		c.Locals(string(handler.ContextKeyTargetUserID), targetUserID)

		// Use slog Debug
		appLogger.Debug("idParamMiddleware: Set TargetUserID in Locals", "target_user_id", targetUserID, "path", path)
		return c.Next()
	}

	// authMiddleware validates the JWT token from the Authorization header
	// and stores the resulting claims in Fiber Locals. Uses slog for logging.
	authMiddleware := func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		path := c.Path() // Get path once

		if authHeader == "" {
			// Use slog Warn
			appLogger.Warn("Auth middleware: Missing Authorization header", "path", path)
			return handler.RespondWithErrorFiber(c, appLogger, "Missing authorization header", fiber.StatusUnauthorized, nil)
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			// Use slog Warn
			appLogger.Warn("Auth middleware: Malformed Authorization header", "header_value", authHeader, "path", path)
			return handler.RespondWithErrorFiber(c, appLogger, "Malformed authorization header", fiber.StatusUnauthorized, nil)
		}

		tokenString := parts[1]
		claims, err := jwtService.ValidateToken(tokenString)
		if err != nil {
			// Use slog Warn for invalid/expired tokens
			status := fiber.StatusUnauthorized
			message := "Invalid or expired token"
			logFields := []any{"path", path, "error", err}

			if errors.Is(err, security.ErrTokenExpired) {
				message = "Token has expired"
				logFields = append(logFields, "reason", "expired")
			} else if errors.Is(err, security.ErrTokenInvalid) {
				message = "Token is invalid"
				logFields = append(logFields, "reason", "invalid")
			} else {
				// Log unexpected validation errors potentially differently if needed
				logFields = append(logFields, "reason", "validation_error")
			}
			appLogger.Warn("Auth middleware: Invalid token", logFields...)
			return handler.RespondWithErrorFiber(c, appLogger, message, status, err)
		}

		// Store Claims in Locals
		c.Locals(string(handler.ContextKeyAuthClaims), claims)

		// Use slog Debug
		appLogger.Debug("Auth middleware: Set Claims in Locals", "user_id", claims.UserID, "role", claims.Role.String(), "path", path)
		return c.Next()
	}

	// --- Routes ---
	apiGroup := app.Group("/api/v1")
	apiGroup.Get("/health", func(c *fiber.Ctx) error {
		// Maybe log health check access if needed
		// appLogger.Debug("Health check accessed", "remote_ip", c.IP())
		return c.Status(http.StatusOK).JSON(fiber.Map{"status": "ok"})
	})

	// User Routes
	userGroup := apiGroup.Group("/users")
	if userHandler != nil {
		appLogger.Info("Registering User routes...")

		// Public routes (still using adaptor as they are http.HandlerFunc)
		// Logging for these happens inside the adapted handler (userHandler.HandleCreateUser/Login)
		userGroup.Post("/", adaptor.HTTPHandlerFunc(userHandler.HandleCreateUser))
		userGroup.Post("/login", adaptor.HTTPHandlerFunc(userHandler.HandleLogin))

		// Protected Routes (using direct Fiber handlers now)
		// Middleware applied in order: Auth -> [ID Param] -> Handler
		// Logging happens within middleware and the final handler
		userGroup.Get("/", authMiddleware, userHandler.HandleListUsers)
		userGroup.Get("/:id", authMiddleware, idParamMiddleware, userHandler.HandleGetUserByID)
		userGroup.Put("/:id", authMiddleware, idParamMiddleware, userHandler.HandleUpdateUserDetails)
		userGroup.Patch("/:id/password", authMiddleware, idParamMiddleware, userHandler.HandleChangePassword)
		userGroup.Patch("/:id/activate", authMiddleware, idParamMiddleware, userHandler.HandleActivateUser)     // Admin only
		userGroup.Patch("/:id/deactivate", authMiddleware, idParamMiddleware, userHandler.HandleDeactivateUser) // Admin only
		userGroup.Delete("/:id", authMiddleware, idParamMiddleware, userHandler.HandleDeleteUser)
	}

	appLogger.Info("Fiber application configured.")
	return app
}
