// internal/infrastructure/web/handler/user_handler.go
package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gofiber/fiber/v2"
	app_service "github.com/mohamedhabas11/ddd-crud/internal/application/service"
	"github.com/mohamedhabas11/ddd-crud/internal/domain/user"
	"github.com/mohamedhabas11/ddd-crud/internal/infrastructure/security"
	"github.com/mohamedhabas11/ddd-crud/internal/infrastructure/web/dto"
)

// --- Context Keys ---
type contextKey string

const (
	ContextKeyAuthClaims   contextKey = "authClaims"
	ContextKeyTargetUserID contextKey = "targetUserID"
)

// UserHandler handles HTTP requests related to users.
type UserHandler struct {
	userService *app_service.UserService
	jwtService  *security.JWTService
	logger      *slog.Logger // <--- CHANGE THIS FIELD TYPE
}

// NewUserHandler creates a new UserHandler.
// CHANGE the logger parameter type here:
func NewUserHandler(
	userService *app_service.UserService,
	jwtService *security.JWTService,
	logger *slog.Logger,
) *UserHandler {
	if userService == nil {
		panic("userService is required for UserHandler")
	}
	if jwtService == nil {
		panic("jwtService is required for UserHandler")
	}
	if logger == nil {
		logger = slog.Default() // Use slog default
		logger.Warn("No logger provided to UserHandler, using default slog logger.")
	}
	return &UserHandler{
		userService: userService,
		jwtService:  jwtService,
		logger:      logger, // Assign slog logger
	}
}

// --- Helper Functions (Fiber versions - Updated for slog) ---

// RespondWithErrorFiber logs the error using slog and sends a JSON error response.
func RespondWithErrorFiber(c *fiber.Ctx, logger *slog.Logger, message string, code int, err error) error {
	logArgs := []any{"status_code", code, "message", message, "path", c.Path()}
	if err != nil {
		logArgs = append(logArgs, "error", err)
		// Log with Error level if an actual error occurred
		logger.Error("HTTP Response Error", logArgs...)
	} else {
		// Log with Warn level for client errors without a Go error object (e.g., bad request format)
		logger.Warn("HTTP Response Error", logArgs...)
	}

	errorResponse := fiber.Map{"error": message}
	return c.Status(code).JSON(errorResponse) // Return the error for Fiber chaining
}

// RespondWithJSONFiber sends a JSON success response. Logging can be added here if needed.
func RespondWithJSONFiber(c *fiber.Ctx, logger *slog.Logger, code int, payload interface{}) error {
	// Optional: Log successful responses if desired (can be verbose)
	// logger.Info("HTTP Response Success", "status_code", code, "path", c.Path())

	if payload != nil {
		return c.Status(code).JSON(payload) // Return the error for Fiber chaining
	}
	// If payload is nil, just send the status code (e.g., for 204 No Content)
	return c.SendStatus(code)
}

// --- Fiber Handlers (Updated for slog) ---

// HandleCreateUser registers a new user (Fiber Handler using Adaptor)
// NOTE: Since this still uses the adaptor for http.HandlerFunc,
// we need to adapt the logging within the original http.HandlerFunc style,
// or fully convert it to a Fiber handler. Let's keep it adapted for now
// but use the injected slog logger.
func (h *UserHandler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateUserRequest
	// We don't have fiber context here, so logging path isn't easy
	// Use a helper or log directly
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		h.logger.Warn("Invalid request body for user creation", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	newUser, err := h.userService.CreateUser(r.Context(), req.Name, req.Email, req.Password, req.Role, req.ShopID)
	if err != nil {
		status := http.StatusInternalServerError
		message := "Failed to create user"
		logLevel := slog.LevelError // Default to error

		switch {
		case errors.Is(err, app_service.ErrEmailExists):
			status = http.StatusConflict
			message = "Email already exists"
			logLevel = slog.LevelWarn // Treat as client error for logging
		case errors.Is(err, app_service.ErrInvalidInput):
			status = http.StatusBadRequest
			message = "Invalid input: " + err.Error() // Include specific validation error
			logLevel = slog.LevelWarn                 // Treat as client error for logging
		}

		h.logger.Log(r.Context(), logLevel, message, "email", req.Email, "error", err) // Use Log for dynamic level
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": message})
		return
	}

	h.logger.Info("User created successfully via adapted handler", "user_id", newUser.ID, "email", newUser.Email)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(dto.ToUserResponse(newUser))
}

// HandleLogin processes user login (Fiber Handler using Adaptor)
// Similar logging adaptation needed as HandleCreateUser
func (h *UserHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		h.logger.Warn("Invalid request body for login", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	authenticatedUser, err := h.userService.AuthenticateUser(r.Context(), req.Email, req.Password)
	if err != nil {
		status := http.StatusInternalServerError
		message := "Login failed"
		logLevel := slog.LevelError

		if errors.Is(err, app_service.ErrAuthentication) {
			status = http.StatusUnauthorized
			message = "Invalid email or password"
			logLevel = slog.LevelWarn // Log failed auth attempts as Warn
		}

		h.logger.Log(r.Context(), logLevel, message, "email", req.Email, "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": message})
		return
	}

	tokenString, err := h.jwtService.GenerateToken(authenticatedUser.ID, authenticatedUser.Role)
	if err != nil {
		h.logger.Error("Failed to generate authentication token", "user_id", authenticatedUser.ID, "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate authentication token"})
		return
	}

	response := dto.AuthResponse{
		User:  dto.ToUserResponse(authenticatedUser),
		Token: tokenString,
	}

	h.logger.Info("User logged in successfully via adapted handler", "user_id", authenticatedUser.ID, "email", authenticatedUser.Email)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleGetUserByID gets the user ID from context and fetches the user (Direct Fiber Handler)
func (h *UserHandler) HandleGetUserByID(c *fiber.Ctx) error {
	h.logger.Debug("HandleGetUserByID [Fiber] - Handler entered.")

	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))
	if targetUserIDVal == nil {
		// Error already logged by middleware potentially, but log here too for clarity
		h.logger.Error("HandleGetUserByID [Fiber] - TargetUserID value from Locals is nil")
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}
	targetUserID, ok := targetUserIDVal.(uint)
	if !ok {
		h.logger.Error("HandleGetUserByID [Fiber] - Failed to assert TargetUserID from Locals", "type", fmt.Sprintf("%T", targetUserIDVal))
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	h.logger.Debug("HandleGetUserByID [Fiber] - Retrieved TargetUserID from Locals", "target_user_id", targetUserID)

	// Authorization Check (Example)
	// claims := c.Locals(string(ContextKeyAuthClaims)).(*security.Claims) // Add nil check
	// if claims != nil && claims.UserID != targetUserID && claims.Role != user.RoleAdmin {
	//     return RespondWithErrorFiber(c, h.logger, "Forbidden", fiber.StatusForbidden, errors.New("insufficient permissions"))
	// }

	foundUser, err := h.userService.GetUserByID(c.UserContext(), targetUserID)
	if err != nil {
		if errors.Is(err, app_service.ErrUserNotFound) {
			// Logged as Info in service, use Warn here for the failed request
			return RespondWithErrorFiber(c, h.logger, "User not found", fiber.StatusNotFound, err)
		}
		// Logged as Error in service, use Error here too
		return RespondWithErrorFiber(c, h.logger, "Failed to retrieve user", fiber.StatusInternalServerError, err)
	}
	h.logger.Info("User retrieved successfully", "target_user_id", targetUserID)
	return RespondWithJSONFiber(c, h.logger, fiber.StatusOK, dto.ToUserResponse(foundUser))
}

// HandleUpdateUserDetails updates user details (Direct Fiber Handler)
func (h *UserHandler) HandleUpdateUserDetails(c *fiber.Ctx) error {
	h.logger.Debug("HandleUpdateUserDetails [Fiber] - Handler entered.")

	// --- Get Target User ID ---
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))
	if targetUserIDVal == nil {
		h.logger.Error("HandleUpdateUserDetails [Fiber] - TargetUserID value from Locals is nil")
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}
	targetUserID, ok := targetUserIDVal.(uint)
	if !ok {
		h.logger.Error("HandleUpdateUserDetails [Fiber] - Failed to assert TargetUserID from Locals", "type", fmt.Sprintf("%T", targetUserIDVal))
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	h.logger.Debug("HandleUpdateUserDetails [Fiber] - Retrieved TargetUserID", "target_user_id", targetUserID)

	// --- Get Authenticated User Claims ---
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	if claimsVal == nil {
		h.logger.Error("HandleUpdateUserDetails [Fiber] - Claims value from Locals is nil")
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
	}
	claims, ok := claimsVal.(*security.Claims)
	if !ok {
		h.logger.Error("HandleUpdateUserDetails [Fiber] - Failed to assert claims from Locals", "type", fmt.Sprintf("%T", claimsVal))
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
	}
	authUserID := claims.UserID
	h.logger.Debug("HandleUpdateUserDetails [Fiber] - Retrieved AuthUserID", "auth_user_id", authUserID)

	// --- Authorization Check ---
	if authUserID != targetUserID /* && claims.Role != user.RoleAdmin */ {
		h.logger.Warn("Authorization failed: User attempted to update another user's details", "auth_user_id", authUserID, "target_user_id", targetUserID)
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Cannot update another user's details", fiber.StatusForbidden, errors.New("user ID mismatch"))
	}

	// --- Decode Request Body ---
	var req dto.UpdateUserDetailsRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.Warn("Failed to parse request body for user update", "target_user_id", targetUserID, "error", err)
		return RespondWithErrorFiber(c, h.logger, "Invalid request body", fiber.StatusBadRequest, err)
	}

	var name, email string
	if req.Name != nil {
		name = *req.Name
	}
	if req.Email != nil {
		email = *req.Email
	}

	// --- Call Service ---
	updatedUser, err := h.userService.UpdateUserDetails(c.UserContext(), targetUserID, name, email)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			return RespondWithErrorFiber(c, h.logger, "User not found", fiber.StatusNotFound, err) // Logged as Warn in service
		case errors.Is(err, app_service.ErrEmailExists):
			return RespondWithErrorFiber(c, h.logger, "Email already exists", fiber.StatusConflict, err) // Logged as Warn in service
		case errors.Is(err, app_service.ErrInvalidInput):
			return RespondWithErrorFiber(c, h.logger, "Invalid input: "+err.Error(), fiber.StatusBadRequest, err) // Logged as Warn in service
		default:
			return RespondWithErrorFiber(c, h.logger, "Failed to update user details", fiber.StatusInternalServerError, err) // Logged as Error in service
		}
	}

	h.logger.Info("User details updated successfully", "target_user_id", targetUserID)
	return RespondWithJSONFiber(c, h.logger, fiber.StatusOK, dto.ToUserResponse(updatedUser))
}

// HandleChangePassword changes the password for the authenticated user (Direct Fiber Handler)
func (h *UserHandler) HandleChangePassword(c *fiber.Ctx) error {
	h.logger.Debug("HandleChangePassword [Fiber] - Handler entered.")

	// --- Get Claims & Target User ID (Combine checks for brevity) ---
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))

	if claimsVal == nil || targetUserIDVal == nil {
		h.logger.Error("HandleChangePassword [Fiber] - Missing claims or target user ID in Locals", "claims_nil", claimsVal == nil, "target_id_nil", targetUserIDVal == nil)
		// Determine more specific error if possible
		if claimsVal == nil {
			return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
		}
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}

	claims, okClaims := claimsVal.(*security.Claims)
	targetUserID, okTargetID := targetUserIDVal.(uint)

	if !okClaims || !okTargetID {
		h.logger.Error("HandleChangePassword [Fiber] - Invalid type for claims or target user ID in Locals", "claims_ok", okClaims, "target_id_ok", okTargetID, "claims_type", fmt.Sprintf("%T", claimsVal), "target_id_type", fmt.Sprintf("%T", targetUserIDVal))
		// Determine more specific error if possible
		if !okClaims {
			return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
		}
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}

	authUserID := claims.UserID
	h.logger.Debug("HandleChangePassword [Fiber] - Retrieved IDs", "auth_user_id", authUserID, "target_user_id", targetUserID)

	// --- Authorization Check ---
	if authUserID != targetUserID /* && claims.Role != user.RoleAdmin */ {
		h.logger.Warn("Authorization failed: User attempted to change another user's password", "auth_user_id", authUserID, "target_user_id", targetUserID)
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Cannot change another user's password", fiber.StatusForbidden, errors.New("user ID mismatch"))
	}

	// --- Decode Request Body ---
	var req dto.ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.Warn("Failed to parse request body for password change", "target_user_id", targetUserID, "error", err)
		return RespondWithErrorFiber(c, h.logger, "Invalid request body", fiber.StatusBadRequest, err)
	}

	// --- Call Service ---
	err := h.userService.ChangePassword(c.UserContext(), targetUserID, req.OldPassword, req.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			// Should not happen if middleware worked, but handle defensively
			return RespondWithErrorFiber(c, h.logger, "User not found", fiber.StatusNotFound, err)
		case errors.Is(err, app_service.ErrCurrentPassword):
			// Log as Warn because it's a client input error
			return RespondWithErrorFiber(c, h.logger, "Incorrect current password", fiber.StatusBadRequest, err)
		case errors.Is(err, app_service.ErrInvalidInput):
			// Log as Warn because it's a client input error
			return RespondWithErrorFiber(c, h.logger, "Invalid input: "+err.Error(), fiber.StatusBadRequest, err)
		default:
			// Log as Error for unexpected service/repo errors
			return RespondWithErrorFiber(c, h.logger, "Failed to change password", fiber.StatusInternalServerError, err)
		}
	}

	h.logger.Info("Password changed successfully", "target_user_id", targetUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// HandleActivateUser activates a user (Admin only - Direct Fiber Handler)
func (h *UserHandler) HandleActivateUser(c *fiber.Ctx) error {
	h.logger.Debug("HandleActivateUser [Fiber] - Handler entered.")

	// --- Get Claims & Target User ID ---
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))

	if claimsVal == nil || targetUserIDVal == nil {
		h.logger.Error("HandleActivateUser [Fiber] - Missing claims or target user ID in Locals", "claims_nil", claimsVal == nil, "target_id_nil", targetUserIDVal == nil)
		// Prioritize auth error
		if claimsVal == nil {
			return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
		}
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}

	claims, okClaims := claimsVal.(*security.Claims)
	targetUserID, okTargetID := targetUserIDVal.(uint)

	if !okClaims || !okTargetID {
		h.logger.Error("HandleActivateUser [Fiber] - Invalid type for claims or target user ID in Locals", "claims_ok", okClaims, "target_id_ok", okTargetID, "claims_type", fmt.Sprintf("%T", claimsVal), "target_id_type", fmt.Sprintf("%T", targetUserIDVal))
		if !okClaims {
			return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
		}
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	h.logger.Debug("HandleActivateUser [Fiber] - Retrieved IDs", "auth_user_id", claims.UserID, "auth_role", claims.Role.String(), "target_user_id", targetUserID)

	// --- Authorization Check: Admin Only ---
	if claims.Role != user.RoleAdmin {
		h.logger.Warn("Authorization failed: Non-admin attempted to activate user", "auth_user_id", claims.UserID, "auth_role", claims.Role.String(), "target_user_id", targetUserID)
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Admin role required", fiber.StatusForbidden, errors.New("insufficient permissions"))
	}

	// --- Call Service ---
	err := h.userService.ActivateUser(c.UserContext(), targetUserID)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			return RespondWithErrorFiber(c, h.logger, "Target user not found", fiber.StatusNotFound, err) // Logged as Warn in service
		default:
			return RespondWithErrorFiber(c, h.logger, "Failed to activate user", fiber.StatusInternalServerError, err) // Logged as Error in service
		}
	}

	h.logger.Info("User activated successfully", "target_user_id", targetUserID, "admin_user_id", claims.UserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// HandleDeactivateUser deactivates a user (Admin only - Direct Fiber Handler)
func (h *UserHandler) HandleDeactivateUser(c *fiber.Ctx) error {
	h.logger.Debug("HandleDeactivateUser [Fiber] - Handler entered.")

	// --- Get Claims & Target User ID --- (Similar checks as Activate)
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))

	if claimsVal == nil || targetUserIDVal == nil {
		h.logger.Error("HandleDeactivateUser [Fiber] - Missing claims or target user ID in Locals", "claims_nil", claimsVal == nil, "target_id_nil", targetUserIDVal == nil)
		if claimsVal == nil {
			return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
		}
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}
	claims, okClaims := claimsVal.(*security.Claims)
	targetUserID, okTargetID := targetUserIDVal.(uint)
	if !okClaims || !okTargetID {
		h.logger.Error("HandleDeactivateUser [Fiber] - Invalid type for claims or target user ID in Locals", "claims_ok", okClaims, "target_id_ok", okTargetID, "claims_type", fmt.Sprintf("%T", claimsVal), "target_id_type", fmt.Sprintf("%T", targetUserIDVal))
		if !okClaims {
			return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
		}
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	h.logger.Debug("HandleDeactivateUser [Fiber] - Retrieved IDs", "auth_user_id", claims.UserID, "auth_role", claims.Role.String(), "target_user_id", targetUserID)

	// --- Authorization Check: Admin Only ---
	if claims.Role != user.RoleAdmin {
		h.logger.Warn("Authorization failed: Non-admin attempted to deactivate user", "auth_user_id", claims.UserID, "auth_role", claims.Role.String(), "target_user_id", targetUserID)
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Admin role required", fiber.StatusForbidden, errors.New("insufficient permissions"))
	}

	// --- Call Service ---
	err := h.userService.DeactivateUser(c.UserContext(), targetUserID)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			return RespondWithErrorFiber(c, h.logger, "Target user not found", fiber.StatusNotFound, err) // Logged as Warn in service
		default:
			return RespondWithErrorFiber(c, h.logger, "Failed to deactivate user", fiber.StatusInternalServerError, err) // Logged as Error in service
		}
	}

	h.logger.Info("User deactivated successfully", "target_user_id", targetUserID, "admin_user_id", claims.UserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// HandleDeleteUser deletes a user (Direct Fiber Handler)
func (h *UserHandler) HandleDeleteUser(c *fiber.Ctx) error {
	h.logger.Debug("HandleDeleteUser [Fiber] - Handler entered.")

	// --- Get Claims & Target User ID --- (Similar checks as Activate/Deactivate)
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))

	if claimsVal == nil || targetUserIDVal == nil {
		h.logger.Error("HandleDeleteUser [Fiber] - Missing claims or target user ID in Locals", "claims_nil", claimsVal == nil, "target_id_nil", targetUserIDVal == nil)
		if claimsVal == nil {
			return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
		}
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}
	claims, okClaims := claimsVal.(*security.Claims)
	targetUserID, okTargetID := targetUserIDVal.(uint)
	if !okClaims || !okTargetID {
		h.logger.Error("HandleDeleteUser [Fiber] - Invalid type for claims or target user ID in Locals", "claims_ok", okClaims, "target_id_ok", okTargetID, "claims_type", fmt.Sprintf("%T", claimsVal), "target_id_type", fmt.Sprintf("%T", targetUserIDVal))
		if !okClaims {
			return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
		}
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	authUserID := claims.UserID
	h.logger.Debug("HandleDeleteUser [Fiber] - Retrieved IDs", "auth_user_id", authUserID, "auth_role", claims.Role.String(), "target_user_id", targetUserID)

	// --- Authorization Check (Self or Admin) ---
	if authUserID != targetUserID && claims.Role != user.RoleAdmin {
		h.logger.Warn("Authorization failed: User attempted to delete another user", "auth_user_id", authUserID, "auth_role", claims.Role.String(), "target_user_id", targetUserID)
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Cannot delete another user", fiber.StatusForbidden, errors.New("insufficient permissions"))
	}

	// --- Call Service ---
	err := h.userService.DeleteUser(c.UserContext(), targetUserID)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			return RespondWithErrorFiber(c, h.logger, "User not found", fiber.StatusNotFound, err) // Logged as Warn in service
		default:
			return RespondWithErrorFiber(c, h.logger, "Failed to delete user", fiber.StatusInternalServerError, err) // Logged as Error in service
		}
	}

	h.logger.Info("User deleted successfully", "target_user_id", targetUserID, "requesting_user_id", authUserID)
	return c.SendStatus(fiber.StatusNoContent)
}

// HandleListUsers lists all users (Admin only - Direct Fiber Handler)
func (h *UserHandler) HandleListUsers(c *fiber.Ctx) error {
	h.logger.Debug("HandleListUsers [Fiber] - Handler entered.")

	// --- Get Claims ---
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	if claimsVal == nil {
		h.logger.Error("HandleListUsers [Fiber] - Claims value from Locals is nil")
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
	}
	claims, ok := claimsVal.(*security.Claims)
	if !ok {
		h.logger.Error("HandleListUsers [Fiber] - Failed to assert claims from Locals", "type", fmt.Sprintf("%T", claimsVal))
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
	}
	h.logger.Debug("HandleListUsers [Fiber] - Retrieved Claims", "auth_user_id", claims.UserID, "auth_role", claims.Role.String())

	// --- Authorization Check: Admin Only ---
	if claims.Role != user.RoleAdmin {
		h.logger.Warn("Authorization failed: Non-admin attempted to list all users", "auth_user_id", claims.UserID, "auth_role", claims.Role.String())
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Admin role required", fiber.StatusForbidden, errors.New("insufficient permissions"))
	}

	// --- Call Service ---
	// TODO: Add pagination from query params: c.QueryInt("limit", 20), c.QueryInt("offset", 0)
	users, err := h.userService.ListAllUsers(c.UserContext() /*, pagination params */)
	if err != nil {
		// Logged as Error in service
		return RespondWithErrorFiber(c, h.logger, "Failed to list users", fiber.StatusInternalServerError, err)
	}

	h.logger.Info("Listed all users successfully", "count", len(users), "admin_user_id", claims.UserID)
	return RespondWithJSONFiber(c, h.logger, fiber.StatusOK, dto.ToUserResponseSlice(users))
}

// --- Deprecated http.HandlerFunc Helpers ---
// Keep these only if you absolutely need to keep using the adaptor for some reason.
// It's generally better to convert all handlers to Fiber handlers.

// import "encoding/json" // Need this if using the helpers below

// func decodeJSONBody(r *http.Request, v interface{}) error {
// 	decoder := json.NewDecoder(r.Body)
// 	err := decoder.Decode(v)
// 	if err != nil {
// 		return fmt.Errorf("failed to decode request body: %w", err)
// 	}
// 	return nil
// }

// func respondWithError(w http.ResponseWriter, logger *slog.Logger, message string, code int, err error) {
// 	logArgs := []any{"status_code", code, "message", message}
// 	logLevel := slog.LevelWarn // Default to Warn for client errors
// 	if err != nil {
// 		logArgs = append(logArgs, "error", err)
// 		if code >= 500 { // Treat server errors as Error level
// 			logLevel = slog.LevelError
// 		}
// 	}
// 	logger.Log(context.Background(), logLevel, "HTTP Response Error (adapted handler)", logArgs...) // No context readily available

// 	errorResponse := map[string]string{"error": message}
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(code)
// 	if encodeErr := json.NewEncoder(w).Encode(errorResponse); encodeErr != nil {
// 		logger.Error("Failed to encode error response (adapted handler)", "error", encodeErr)
// 	}
// }

// func respondWithJSON(w http.ResponseWriter, logger *slog.Logger, code int, payload interface{}) {
// 	// Optional: logger.Info("HTTP Response Success (adapted handler)", "status_code", code)
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(code)
// 	if payload != nil {
// 		if err := json.NewEncoder(w).Encode(payload); err != nil {
// 			logger.Error("Failed to encode JSON response (adapted handler)", "error", err)
// 		}
// 	}
// }
