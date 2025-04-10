// internal/infrastructure/web/handler/user_handler.go
package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2" // Import fiber
	app_service "github.com/mohamedhabas11/ddd-crud/internal/application/service"
	"github.com/mohamedhabas11/ddd-crud/internal/domain/user"             // Import user for Role
	"github.com/mohamedhabas11/ddd-crud/internal/infrastructure/security" // Import security for Claims
	"github.com/mohamedhabas11/ddd-crud/internal/infrastructure/web/dto"
)

// --- Context Keys (Now primarily for Locals, but keep definitions) ---
type contextKey string

const (
	ContextKeyAuthClaims   contextKey = "authClaims"   // Key for JWT claims object in Locals
	ContextKeyTargetUserID contextKey = "targetUserID" // Key for the user ID from the URL path in Locals
)

// UserHandler handles HTTP requests related to users.
type UserHandler struct {
	userService *app_service.UserService
	jwtService  *security.JWTService
	logger      *log.Logger
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(
	userService *app_service.UserService,
	jwtService *security.JWTService,
	logger *log.Logger,
) *UserHandler {
	if userService == nil {
		panic("userService is required for UserHandler")
	}
	if jwtService == nil {
		panic("jwtService is required for UserHandler")
	}
	if logger == nil {
		logger = log.Default()
		logger.Println("WARN: No logger provided to UserHandler, using default log package.")
	}
	return &UserHandler{
		userService: userService,
		jwtService:  jwtService,
		logger:      logger,
	}
}

// --- Helper Functions (Original for http.HandlerFunc) ---
func decodeJSONBody(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(v)
	if err != nil {
		return fmt.Errorf("failed to decode request body: %w", err)
	}
	return nil
}

func respondWithError(w http.ResponseWriter, logger *log.Logger, message string, code int, err error) {
	if err != nil {
		logger.Printf("ERROR: HTTP %d - %s: %v", code, message, err)
	} else {
		logger.Printf("WARN: HTTP %d - %s", code, message)
	}
	errorResponse := map[string]string{"error": message}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if encodeErr := json.NewEncoder(w).Encode(errorResponse); encodeErr != nil {
		logger.Printf("ERROR: Failed to encode error response: %v", encodeErr)
	}
}

func respondWithJSON(w http.ResponseWriter, logger *log.Logger, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if payload != nil {
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			logger.Printf("ERROR: Failed to encode JSON response: %v", err)
		}
	}
}

// --- Helper Functions (Fiber versions) ---

func RespondWithErrorFiber(c *fiber.Ctx, logger *log.Logger, message string, code int, err error) error {
	if err != nil {
		logger.Printf("ERROR: Fiber HTTP %d - %s: %v", code, message, err)
	} else {
		logger.Printf("WARN: Fiber HTTP %d - %s", code, message)
	}
	errorResponse := fiber.Map{"error": message}
	return c.Status(code).JSON(errorResponse) // Return the error for Fiber chaining
}

func RespondWithJSONFiber(c *fiber.Ctx, logger *log.Logger, code int, payload interface{}) error {
	if payload != nil {
		return c.Status(code).JSON(payload) // Return the error for Fiber chaining
	}
	// If payload is nil, just send the status code (e.g., for 204 No Content)
	return c.SendStatus(code)
}

// --- Original Handlers (Using http.HandlerFunc) ---

// HandleCreateUser registers a new user
func (h *UserHandler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateUserRequest
	if err := decodeJSONBody(r, &req); err != nil {
		respondWithError(w, h.logger, "Invalid request body", http.StatusBadRequest, err)
		return
	}

	newUser, err := h.userService.CreateUser(r.Context(), req.Name, req.Email, req.Password, req.Role, req.ShopID)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrEmailExists):
			respondWithError(w, h.logger, "Email already exists", http.StatusConflict, err)
		case errors.Is(err, app_service.ErrInvalidInput):
			respondWithError(w, h.logger, "Invalid input: "+err.Error(), http.StatusBadRequest, err)
		default:
			respondWithError(w, h.logger, "Failed to create user", http.StatusInternalServerError, err)
		}
		return
	}
	respondWithJSON(w, h.logger, http.StatusCreated, dto.ToUserResponse(newUser))
}

// HandleLogin processes user login and returns a JWT token
func (h *UserHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if err := decodeJSONBody(r, &req); err != nil {
		respondWithError(w, h.logger, "Invalid request body", http.StatusBadRequest, err)
		return
	}

	authenticatedUser, err := h.userService.AuthenticateUser(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, app_service.ErrAuthentication) {
			respondWithError(w, h.logger, "Invalid email or password", http.StatusUnauthorized, err)
		} else {
			respondWithError(w, h.logger, "Login failed", http.StatusInternalServerError, err)
		}
		return
	}

	tokenString, err := h.jwtService.GenerateToken(authenticatedUser.ID, authenticatedUser.Role)
	if err != nil {
		respondWithError(w, h.logger, "Failed to generate authentication token", http.StatusInternalServerError, err)
		return
	}

	response := dto.AuthResponse{
		User:  dto.ToUserResponse(authenticatedUser),
		Token: tokenString,
	}

	respondWithJSON(w, h.logger, http.StatusOK, response)
}

// HandleGetUserByID gets the user ID from context and fetches the user.
func (h *UserHandler) HandleGetUserByID(c *fiber.Ctx) error { // Changed signature
	h.logger.Println("DEBUG: HandleGetUserByID [Fiber] - Handler entered.")

	// --- Get Target User ID from Fiber Context (Locals) ---
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))
	if targetUserIDVal == nil {
		h.logger.Println("ERROR: HandleGetUserByID [Fiber] - TargetUserID value from Locals is nil")
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}
	targetUserID, ok := targetUserIDVal.(uint)
	if !ok {
		h.logger.Printf("ERROR: HandleGetUserByID [Fiber] - Failed to assert TargetUserID from Locals. Type was %T", targetUserIDVal)
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	h.logger.Printf("DEBUG: HandleGetUserByID [Fiber] - Successfully retrieved TargetUserID: %d from Locals", targetUserID)
	// --- End Get Target User ID ---

	// --- Get Authenticated User Claims (Optional - for authorization if needed) ---
	// claimsVal := c.Locals(string(ContextKeyAuthClaims))
	// claims, _ := claimsVal.(*security.Claims)
	// if claims == nil { ... handle error ... }
	// --- End Get Authenticated User Claims ---

	// Authorization Check (Example: User can only get their own details unless Admin)
	// if claims.UserID != targetUserID && claims.Role != user.RoleAdmin {
	//     return RespondWithErrorFiber(c, h.logger, "Forbidden", fiber.StatusForbidden, errors.New("insufficient permissions"))
	// }

	foundUser, err := h.userService.GetUserByID(c.UserContext(), targetUserID)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			return RespondWithErrorFiber(c, h.logger, "User not found", fiber.StatusNotFound, err)
		default:
			return RespondWithErrorFiber(c, h.logger, "Failed to retrieve user", fiber.StatusInternalServerError, err)
		}
	}
	return RespondWithJSONFiber(c, h.logger, fiber.StatusOK, dto.ToUserResponse(foundUser))
}

// HandleUpdateUserDetails updates user details.
func (h *UserHandler) HandleUpdateUserDetails(c *fiber.Ctx) error { // Changed signature
	h.logger.Println("DEBUG: HandleUpdateUserDetails [Fiber] - Handler entered.")

	// --- Get Target User ID from Fiber Context (Locals) ---
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))
	if targetUserIDVal == nil {
		h.logger.Println("ERROR: HandleUpdateUserDetails [Fiber] - TargetUserID value from Locals is nil")
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}
	targetUserID, ok := targetUserIDVal.(uint)
	if !ok {
		h.logger.Printf("ERROR: HandleUpdateUserDetails [Fiber] - Failed to assert TargetUserID from Locals. Type was %T", targetUserIDVal)
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	h.logger.Printf("DEBUG: HandleUpdateUserDetails [Fiber] - Successfully retrieved TargetUserID: %d from Locals", targetUserID)
	// --- End Get Target User ID ---

	// --- Get Authenticated User Claims from Fiber Context (Locals) ---
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	if claimsVal == nil {
		h.logger.Println("ERROR: HandleUpdateUserDetails [Fiber] - Claims value from Locals is nil")
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
	}
	claims, ok := claimsVal.(*security.Claims)
	if !ok {
		h.logger.Printf("ERROR: HandleUpdateUserDetails [Fiber] - Failed to assert claims from Locals. Type was %T", claimsVal)
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
	}
	authUserID := claims.UserID
	h.logger.Printf("DEBUG: HandleUpdateUserDetails [Fiber] - Successfully retrieved AuthUserID: %d from Locals", authUserID)
	// --- End Get Authenticated User Claims ---

	// Authorization Check (User can only update their own details unless Admin)
	if authUserID != targetUserID /* && claims.Role != user.RoleAdmin */ {
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Cannot update another user's details", fiber.StatusForbidden, errors.New("user ID mismatch"))
	}

	// Decode Request Body
	var req dto.UpdateUserDetailsRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.Printf("ERROR: HandleUpdateUserDetails [Fiber] - Failed to parse request body: %v", err)
		return RespondWithErrorFiber(c, h.logger, "Invalid request body", fiber.StatusBadRequest, err)
	}

	var name, email string
	if req.Name != nil {
		name = *req.Name
	}
	if req.Email != nil {
		email = *req.Email
	}

	updatedUser, err := h.userService.UpdateUserDetails(c.UserContext(), targetUserID, name, email)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			return RespondWithErrorFiber(c, h.logger, "User not found", fiber.StatusNotFound, err)
		case errors.Is(err, app_service.ErrEmailExists):
			return RespondWithErrorFiber(c, h.logger, "Email already exists", fiber.StatusConflict, err)
		case errors.Is(err, app_service.ErrInvalidInput):
			return RespondWithErrorFiber(c, h.logger, "Invalid input: "+err.Error(), fiber.StatusBadRequest, err)
		default:
			return RespondWithErrorFiber(c, h.logger, "Failed to update user details", fiber.StatusInternalServerError, err)
		}
	}
	return RespondWithJSONFiber(c, h.logger, fiber.StatusOK, dto.ToUserResponse(updatedUser))
}

// HandleChangePassword changes the password for the authenticated user (Fiber Handler)
func (h *UserHandler) HandleChangePassword(c *fiber.Ctx) error { // Changed signature
	h.logger.Println("DEBUG: HandleChangePassword [Fiber] - Handler entered.")

	// --- Get Authenticated User Claims from Fiber Context (Locals) ---
	claimsVal := c.Locals(string(ContextKeyAuthClaims)) // Use string key for Locals
	if claimsVal == nil {
		h.logger.Println("ERROR: HandleChangePassword [Fiber] - Claims value from Locals is nil")
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
	}

	claims, ok := claimsVal.(*security.Claims)
	if !ok {
		h.logger.Printf("ERROR: HandleChangePassword [Fiber] - Failed to assert claims from Locals. Type was %T", claimsVal)
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
	}
	authUserID := claims.UserID
	h.logger.Printf("DEBUG: HandleChangePassword [Fiber] - Successfully retrieved AuthUserID: %d from Locals", authUserID)
	// --- End Get Authenticated User Claims ---

	// --- Get Target User ID from Fiber Context (Locals) ---
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID)) // Use string key for Locals
	if targetUserIDVal == nil {
		h.logger.Println("ERROR: HandleChangePassword [Fiber] - TargetUserID value from Locals is nil")
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}

	targetUserID, ok := targetUserIDVal.(uint)
	if !ok {
		h.logger.Printf("ERROR: HandleChangePassword [Fiber] - Failed to assert TargetUserID from Locals. Type was %T", targetUserIDVal)
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	h.logger.Printf("DEBUG: HandleChangePassword [Fiber] - Successfully retrieved TargetUserID: %d from Locals", targetUserID)
	// --- End Get Target User ID ---

	h.logger.Printf("DEBUG: HandleChangePassword [Fiber] - AuthUserID: %d, TargetUserID: %d", authUserID, targetUserID)

	// Authorization Check
	if authUserID != targetUserID {
		// Example: Allow Admins to change anyone's password
		// if claims.Role != user.RoleAdmin {
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Cannot change another user's password", fiber.StatusForbidden, errors.New("user ID mismatch"))
		// }
	}

	// Decode Request Body using Fiber context
	var req dto.ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil { // Use c.BodyParser
		h.logger.Printf("ERROR: HandleChangePassword [Fiber] - Failed to parse request body: %v", err)
		return RespondWithErrorFiber(c, h.logger, "Invalid request body", fiber.StatusBadRequest, err)
	}

	// Call Service using the Target User ID and Fiber's Go context
	err := h.userService.ChangePassword(c.UserContext(), targetUserID, req.OldPassword, req.NewPassword)
	if err != nil {
		// Map service errors to Fiber responses
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			// Should ideally not happen if middleware found the ID, but good practice
			return RespondWithErrorFiber(c, h.logger, "User not found", fiber.StatusNotFound, err)
		case errors.Is(err, app_service.ErrCurrentPassword):
			return RespondWithErrorFiber(c, h.logger, "Incorrect current password", fiber.StatusBadRequest, err) // Use 400 Bad Request
		case errors.Is(err, app_service.ErrInvalidInput):
			return RespondWithErrorFiber(c, h.logger, "Invalid input: "+err.Error(), fiber.StatusBadRequest, err)
		default:
			return RespondWithErrorFiber(c, h.logger, "Failed to change password", fiber.StatusInternalServerError, err)
		}
	}

	// Use Fiber's way to send No Content
	return c.SendStatus(fiber.StatusNoContent)
}

// HandleActivateUser activates a user (Admin only).
func (h *UserHandler) HandleActivateUser(c *fiber.Ctx) error { // Changed signature
	h.logger.Println("DEBUG: HandleActivateUser [Fiber] - Handler entered.")

	// --- Get Authenticated User Claims from Fiber Context (Locals) ---
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	if claimsVal == nil {
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
	}
	claims, ok := claimsVal.(*security.Claims)
	if !ok {
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
	}
	h.logger.Printf("DEBUG: HandleActivateUser [Fiber] - Auth Role: %s", claims.Role.String())
	// --- End Get Authenticated User Claims ---

	// Authorization Check: Admin Only
	if claims.Role != user.RoleAdmin {
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Admin role required", fiber.StatusForbidden, errors.New("insufficient permissions"))
	}

	// --- Get Target User ID from Fiber Context (Locals) ---
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))
	if targetUserIDVal == nil {
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}
	targetUserID, ok := targetUserIDVal.(uint)
	if !ok {
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	h.logger.Printf("DEBUG: HandleActivateUser [Fiber] - TargetUserID: %d", targetUserID)
	// --- End Get Target User ID ---

	err := h.userService.ActivateUser(c.UserContext(), targetUserID)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			return RespondWithErrorFiber(c, h.logger, "Target user not found", fiber.StatusNotFound, err)
		default:
			return RespondWithErrorFiber(c, h.logger, "Failed to activate user", fiber.StatusInternalServerError, err)
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// HandleDeactivateUser deactivates a user (Admin only).
func (h *UserHandler) HandleDeactivateUser(c *fiber.Ctx) error { // Changed signature
	h.logger.Println("DEBUG: HandleDeactivateUser [Fiber] - Handler entered.")

	// --- Get Authenticated User Claims from Fiber Context (Locals) ---
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	if claimsVal == nil {
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
	}
	claims, ok := claimsVal.(*security.Claims)
	if !ok {
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
	}
	h.logger.Printf("DEBUG: HandleDeactivateUser [Fiber] - Auth Role: %s", claims.Role.String())
	// --- End Get Authenticated User Claims ---

	// Authorization Check: Admin Only
	if claims.Role != user.RoleAdmin {
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Admin role required", fiber.StatusForbidden, errors.New("insufficient permissions"))
	}

	// --- Get Target User ID from Fiber Context (Locals) ---
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))
	if targetUserIDVal == nil {
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}
	targetUserID, ok := targetUserIDVal.(uint)
	if !ok {
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	h.logger.Printf("DEBUG: HandleDeactivateUser [Fiber] - TargetUserID: %d", targetUserID)
	// --- End Get Target User ID ---

	err := h.userService.DeactivateUser(c.UserContext(), targetUserID)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			return RespondWithErrorFiber(c, h.logger, "Target user not found", fiber.StatusNotFound, err)
		default:
			return RespondWithErrorFiber(c, h.logger, "Failed to deactivate user", fiber.StatusInternalServerError, err)
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// HandleDeleteUser deletes a user.
func (h *UserHandler) HandleDeleteUser(c *fiber.Ctx) error { // Changed signature
	h.logger.Println("DEBUG: HandleDeleteUser [Fiber] - Handler entered.")

	// --- Get Target User ID from Fiber Context (Locals) ---
	targetUserIDVal := c.Locals(string(ContextKeyTargetUserID))
	if targetUserIDVal == nil {
		return RespondWithErrorFiber(c, h.logger, "Internal server error (missing target user ID)", fiber.StatusInternalServerError, errors.New("target user ID not found in locals"))
	}
	targetUserID, ok := targetUserIDVal.(uint)
	if !ok {
		return RespondWithErrorFiber(c, h.logger, "Internal server error (invalid target user ID type)", fiber.StatusInternalServerError, errors.New("invalid target user ID type in locals"))
	}
	h.logger.Printf("DEBUG: HandleDeleteUser [Fiber] - TargetUserID: %d", targetUserID)
	// --- End Get Target User ID ---

	// --- Get Authenticated User Claims from Fiber Context (Locals) ---
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	if claimsVal == nil {
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
	}
	claims, ok := claimsVal.(*security.Claims)
	if !ok {
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
	}
	authUserID := claims.UserID
	h.logger.Printf("DEBUG: HandleDeleteUser [Fiber] - AuthUserID: %d", authUserID)
	// --- End Get Authenticated User Claims ---

	// Authorization Check (User can delete self, Admin can delete anyone)
	if authUserID != targetUserID && claims.Role != user.RoleAdmin {
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Cannot delete another user", fiber.StatusForbidden, errors.New("insufficient permissions"))
	}

	err := h.userService.DeleteUser(c.UserContext(), targetUserID)
	if err != nil {
		switch {
		case errors.Is(err, app_service.ErrUserNotFound):
			return RespondWithErrorFiber(c, h.logger, "User not found", fiber.StatusNotFound, err)
		default:
			return RespondWithErrorFiber(c, h.logger, "Failed to delete user", fiber.StatusInternalServerError, err)
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// HandleListUsers lists all users (Admin only).
func (h *UserHandler) HandleListUsers(c *fiber.Ctx) error { // Changed signature
	h.logger.Println("DEBUG: HandleListUsers [Fiber] - Handler entered.")

	// --- Get Authenticated User Claims from Fiber Context (Locals) ---
	claimsVal := c.Locals(string(ContextKeyAuthClaims))
	if claimsVal == nil {
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (claims missing)", fiber.StatusUnauthorized, errors.New("auth claims not found in locals"))
	}
	claims, ok := claimsVal.(*security.Claims)
	if !ok {
		return RespondWithErrorFiber(c, h.logger, "Authentication failed (invalid claims type)", fiber.StatusUnauthorized, errors.New("invalid auth claims type in locals"))
	}
	h.logger.Printf("DEBUG: HandleListUsers [Fiber] - Auth Role: %s", claims.Role.String())
	// --- End Get Authenticated User Claims ---

	// Authorization Check: Admin Only
	if claims.Role != user.RoleAdmin {
		return RespondWithErrorFiber(c, h.logger, "Forbidden: Admin role required", fiber.StatusForbidden, errors.New("insufficient permissions"))
	}

	// TODO: Add pagination parameters from query string (e.g., c.Query("limit"), c.Query("offset"))
	users, err := h.userService.ListAllUsers(c.UserContext() /*, pagination params */)
	if err != nil {
		return RespondWithErrorFiber(c, h.logger, "Failed to list users", fiber.StatusInternalServerError, err)
	}
	return RespondWithJSONFiber(c, h.logger, fiber.StatusOK, dto.ToUserResponseSlice(users))
}
