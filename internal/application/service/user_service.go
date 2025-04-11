// internal/application/service/user_service.go
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/mohamedhabas11/ddd-crud/internal/domain/user"
)

// Define application-level errors (consider moving to pkg/apperrors)
var (
	ErrUserNotFound     = errors.New("user not found")
	ErrEmailExists      = errors.New("email already exists")
	ErrAuthentication   = errors.New("authentication failed") // Generic auth error
	ErrCurrentPassword  = errors.New("current password does not match")
	ErrInvalidInput     = errors.New("invalid input provided")
	ErrCreateUserFailed = errors.New("failed to create user")
	ErrUpdateUserFailed = errors.New("failed to update user")
	ErrDeleteUserFailed = errors.New("failed to delete user")
	ErrListUsersFailed  = errors.New("failed to list users") // Added
	ErrUnexpected       = errors.New("an unexpected error occurred")
)

// UserService provides application logic for user operations.
type UserService struct {
	userRepo   user.UserRepository
	userLogger *slog.Logger
}

// NewUserService creates a new UserService instance.
func NewUserService(userRepo user.UserRepository, userLogger *slog.Logger) *UserService { // Correct type
	if userRepo == nil {
		panic("userRepository is required for UserService")
	}
	if userLogger == nil {
		userLogger = slog.Default()
		userLogger.Warn("No logger provided to UserService, using default slog logger.")
	}
	return &UserService{
		userRepo:   userRepo,
		userLogger: userLogger,
	}
}

// ---* Service methods *---

// CreateUser handles the logic for creating a new user.
func (s *UserService) CreateUser(ctx context.Context, name, email, plainPassword, roleStr, shopIDStr string) (*user.User, error) {
	// Use slog Info with key-value pairs
	s.userLogger.Info("Attempting to create user", "email", email)

	// 1. Check if email already exists
	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		// Use slog Error
		s.userLogger.Error("Failed checking email existence during creation", "email", email, "error", err)
		return nil, ErrUnexpected // Return a generic error for unexpected repo issues
	}
	if existing != nil {
		// Use slog Warn for expected business rule violations
		s.userLogger.Warn("Email already exists", "email", email, "existing_user_id", existing.ID)
		return nil, ErrEmailExists
	}

	// 2. Parse role string to Role type
	userRole, err := user.ParseRole(roleStr)
	if err != nil {
		// Use slog Warn for invalid input
		s.userLogger.Warn("Invalid role provided during creation", "role_input", roleStr, "error", err)
		return nil, fmt.Errorf("%w: invalid role '%s'", ErrInvalidInput, roleStr)
	}

	// 3. Convert shopID string to *uint if provided
	var shopIDPtr *uint
	if shopIDStr != "" {
		shopIDUint64, err := strconv.ParseUint(shopIDStr, 10, 32)
		if err != nil {
			s.userLogger.Warn("Invalid shop ID format provided during creation", "shop_id_input", shopIDStr, "error", err)
			return nil, fmt.Errorf("%w: invalid shop ID format '%s'", ErrInvalidInput, shopIDStr)
		}
		shopIDUint := uint(shopIDUint64)
		shopIDPtr = &shopIDUint
	}

	// 4. Create new domain user object using the factory function
	newUser, err := user.NewUser(name, email, plainPassword, userRole, shopIDPtr)
	if err != nil {
		// Use slog Warn for domain validation errors
		s.userLogger.Warn("Domain validation failed creating user", "email", email, "error", err)
		// Wrap the specific validation error from the domain
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	// 5. Persist the user using the repository
	s.userLogger.Info("Persisting new user", "email", email, "role", userRole.String())
	err = s.userRepo.Create(ctx, newUser)
	if err != nil {
		// Use slog Error for repository failures
		// The repository should log the specific DB error, service logs the context
		s.userLogger.Error("Failed to save user to repository", "email", email, "error", err)
		// Wrap the specific repository error if needed, or use a service-level error
		return nil, fmt.Errorf("%w: %v", ErrCreateUserFailed, err)
	}

	// Use slog Info for success
	s.userLogger.Info("Successfully created user", "user_id", newUser.ID, "email", newUser.Email)
	return newUser, nil
}

// AuthenticateUser handles user login verification.
func (s *UserService) AuthenticateUser(ctx context.Context, email, plainPassword string) (*user.User, error) {
	s.userLogger.Info("Attempting authentication", "email", email)

	// 1. Find user by email using the repository
	foundUser, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Use Warn for failed auth attempt (user not found)
			s.userLogger.Warn("Authentication failed - user not found", "email", email)
			return nil, ErrAuthentication // Return generic auth error to handler
		}
		// Use Error for unexpected repository errors
		s.userLogger.Error("Failed finding user during authentication", "email", email, "error", err)
		return nil, ErrUnexpected
	}

	// 2. Check if the user account is active
	if !foundUser.IsActive {
		// Use Warn for failed auth attempt (inactive user)
		s.userLogger.Warn("Authentication failed - user inactive", "email", email, "user_id", foundUser.ID)
		return nil, ErrAuthentication // Return generic auth error
	}

	// 3. Check the password using the domain entity's method
	if !foundUser.CheckPassword(plainPassword) {
		// Use Warn for failed auth attempt (invalid password)
		s.userLogger.Warn("Authentication failed - invalid password", "email", email, "user_id", foundUser.ID)
		return nil, ErrAuthentication // Return generic auth error
	}

	// 4. Authentication successful
	s.userLogger.Info("Authentication successful", "email", email, "user_id", foundUser.ID)
	return foundUser, nil
}

// GetUserByID retrieves a user by their ID.
func (s *UserService) GetUserByID(ctx context.Context, id uint) (*user.User, error) {
	s.userLogger.Info("Attempting to get user by ID", "user_id", id)

	// 1. Find user by ID using the repository
	foundUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Use Info as finding nothing might be expected in some flows
			s.userLogger.Info("User not found by ID", "user_id", id)
			return nil, ErrUserNotFound // Return specific error
		}
		// Use Error for unexpected repository errors
		s.userLogger.Error("Failed finding user by ID", "user_id", id, "error", err)
		return nil, ErrUnexpected
	}

	// 2. User found, return the domain object
	s.userLogger.Info("Successfully retrieved user by ID", "user_id", id)
	return foundUser, nil
}

// UpdateUserDetails updates non-sensitive user details.
func (s *UserService) UpdateUserDetails(ctx context.Context, id uint, name, email string) (*user.User, error) {
	s.userLogger.Info("Attempting to update details for user", "user_id", id)

	// 1. Fetch the existing user
	currentUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Warn("Cannot update details - user not found", "user_id", id)
			return nil, ErrUserNotFound
		}
		s.userLogger.Error("Failed finding user for update", "user_id", id, "error", err)
		return nil, ErrUnexpected
	}

	// 2. Apply changes if inputs are provided
	madeChanges := false
	logFields := []any{"user_id", id} // Collect fields to log later

	// Update Name
	if name != "" && currentUser.Name != name {
		s.userLogger.Info("Updating name for user", "user_id", id, "old_name", currentUser.Name, "new_name", name)
		currentUser.Name = name
		madeChanges = true
		logFields = append(logFields, "name_updated", true)
	}

	// Update Email
	normalizedNewEmail := strings.ToLower(strings.TrimSpace(email))
	if normalizedNewEmail != "" && currentUser.Email != normalizedNewEmail {
		s.userLogger.Info("Attempting to update email for user", "user_id", id, "old_email", currentUser.Email, "new_email", normalizedNewEmail)
		logFields = append(logFields, "email_update_attempted", true, "new_email", normalizedNewEmail)

		// Check if the new email is already taken by *another* user
		existingUserWithEmail, findErr := s.userRepo.FindByEmail(ctx, normalizedNewEmail)
		if findErr != nil && !errors.Is(findErr, ErrUserNotFound) {
			s.userLogger.Error("Failed checking email existence during update", "user_id", id, "check_email", normalizedNewEmail, "error", findErr)
			return nil, ErrUnexpected
		}
		if existingUserWithEmail != nil && existingUserWithEmail.ID != currentUser.ID {
			s.userLogger.Warn("Cannot update email - email already taken", "user_id", id, "new_email", normalizedNewEmail, "taken_by_user_id", existingUserWithEmail.ID)
			return nil, ErrEmailExists
		}

		currentUser.Email = normalizedNewEmail
		madeChanges = true
		logFields = append(logFields, "email_updated", true)
	}

	// 3. Persist changes if any were made
	if !madeChanges {
		s.userLogger.Info("No details changed for user", "user_id", id)
		return currentUser, nil
	}

	s.userLogger.Info("Saving updated details for user", logFields...)
	err = s.userRepo.Update(ctx, currentUser)
	if err != nil {
		// Repo logs specific DB error
		s.userLogger.Error("Failed to save updated user details", "user_id", id, "error", err)
		if errors.Is(err, ErrUserNotFound) { // Should not happen if FindByID succeeded, but check defensively
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrUpdateUserFailed, err)
	}

	s.userLogger.Info("Successfully updated details for user", "user_id", id)
	return currentUser, nil
}

// ChangePassword handles changing a user's password.
func (s *UserService) ChangePassword(ctx context.Context, id uint, oldPassword, newPassword string) error {
	s.userLogger.Info("Attempting to change password for user", "user_id", id)

	// 1. Fetch the existing user
	currentUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Warn("Cannot change password - user not found", "user_id", id)
			return ErrUserNotFound
		}
		s.userLogger.Error("Failed finding user for password change", "user_id", id, "error", err)
		return ErrUnexpected
	}

	// 2. Verify the current (old) password
	if !currentUser.CheckPassword(oldPassword) {
		s.userLogger.Warn("Invalid current password provided for password change", "user_id", id)
		return ErrCurrentPassword
	}

	// 3. Set the new password using the domain method
	err = currentUser.SetPassword(newPassword)
	if err != nil {
		s.userLogger.Warn("Domain validation failed setting new password", "user_id", id, "error", err)
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	// 4. Persist the updated user
	s.userLogger.Info("Saving new password hash for user", "user_id", id)
	err = s.userRepo.Update(ctx, currentUser)
	if err != nil {
		s.userLogger.Error("Failed to save updated password", "user_id", id, "error", err)
		if errors.Is(err, ErrUserNotFound) { // Defensive check
			return ErrUserNotFound
		}
		return fmt.Errorf("%w: %v", ErrUpdateUserFailed, err)
	}

	s.userLogger.Info("Successfully changed password for user", "user_id", id)
	return nil
}

// ActivateUser marks a user account as active.
func (s *UserService) ActivateUser(ctx context.Context, id uint) error {
	s.userLogger.Info("Attempting to activate user", "user_id", id)

	// 1. Fetch the user
	currentUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Warn("Cannot activate user - user not found", "user_id", id)
			return ErrUserNotFound
		}
		s.userLogger.Error("Failed finding user for activation", "user_id", id, "error", err)
		return ErrUnexpected
	}

	// 2. Check if already active (idempotency)
	if currentUser.IsActive {
		s.userLogger.Info("User is already active", "user_id", id)
		return nil // No change needed
	}

	// 3. Use domain method to activate
	currentUser.Activate() // This also updates the UpdatedAt timestamp

	// 4. Persist the change
	s.userLogger.Info("Saving activation status for user", "user_id", id)
	err = s.userRepo.Update(ctx, currentUser)
	if err != nil {
		s.userLogger.Error("Failed to save activation status", "user_id", id, "error", err)
		if errors.Is(err, ErrUserNotFound) { // Defensive check
			return ErrUserNotFound
		}
		return fmt.Errorf("%w: %v", ErrUpdateUserFailed, err)
	}

	s.userLogger.Info("Successfully activated user", "user_id", id)
	return nil
}

// DeactivateUser marks a user account as inactive.
func (s *UserService) DeactivateUser(ctx context.Context, id uint) error {
	s.userLogger.Info("Attempting to deactivate user", "user_id", id)

	// 1. Fetch the user
	currentUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Warn("Cannot deactivate user - user not found", "user_id", id)
			return ErrUserNotFound
		}
		s.userLogger.Error("Failed finding user for deactivation", "user_id", id, "error", err)
		return ErrUnexpected
	}

	// 2. Check if already inactive (idempotency)
	if !currentUser.IsActive {
		s.userLogger.Info("User is already inactive", "user_id", id)
		return nil // No change needed
	}

	// 3. Use domain method to deactivate
	currentUser.Deactivate() // This also updates the UpdatedAt timestamp

	// 4. Persist the change
	s.userLogger.Info("Saving deactivation status for user", "user_id", id)
	err = s.userRepo.Update(ctx, currentUser)
	if err != nil {
		s.userLogger.Error("Failed to save deactivation status", "user_id", id, "error", err)
		if errors.Is(err, ErrUserNotFound) { // Defensive check
			return ErrUserNotFound
		}
		return fmt.Errorf("%w: %v", ErrUpdateUserFailed, err)
	}

	s.userLogger.Info("Successfully deactivated user", "user_id", id)
	return nil
}

// DeleteUser removes a user from the system.
func (s *UserService) DeleteUser(ctx context.Context, id uint) error {
	s.userLogger.Info("Attempting to delete user", "user_id", id)

	// Directly call the repository's Delete method.
	err := s.userRepo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Repo logs Warn, service logs Warn too
			s.userLogger.Warn("Cannot delete user - user not found", "user_id", id)
			return ErrUserNotFound
		}
		// Handle other potential repository errors
		s.userLogger.Error("Failed to delete user", "user_id", id, "error", err)
		return fmt.Errorf("%w: %v", ErrDeleteUserFailed, err)
	}

	s.userLogger.Info("Successfully deleted user", "user_id", id)
	return nil
}

// ListUsersByShop retrieves users associated with a specific shop.
func (s *UserService) ListUsersByShop(ctx context.Context, shopID uint) ([]*user.User, error) {
	s.userLogger.Info("Attempting to list users by shop", "shop_id", shopID)

	users, err := s.userRepo.ListByShop(ctx, shopID)
	if err != nil {
		// Repo logs Error
		s.userLogger.Error("Failed to list users by shop", "shop_id", shopID, "error", err)
		return nil, fmt.Errorf("%w: %v", ErrListUsersFailed, err)
	}

	s.userLogger.Info("Successfully listed users by shop", "shop_id", shopID, "count", len(users))
	return users, nil
}

// ListUsersByRole retrieves users with a specific role.
func (s *UserService) ListUsersByRole(ctx context.Context, role user.Role) ([]*user.User, error) {
	roleStr := role.String()
	s.userLogger.Info("Attempting to list users by role", "role", roleStr)

	// Validate role just in case (though usually handled at input)
	if !role.IsValidRole() {
		err := fmt.Errorf("%w: invalid role '%s'", ErrInvalidInput, roleStr)
		s.userLogger.Warn("Invalid role provided for listing", "role_input", roleStr, "error", err)
		return nil, err
	}

	users, err := s.userRepo.ListByRole(ctx, role)
	if err != nil {
		s.userLogger.Error("Failed to list users by role", "role", roleStr, "error", err)
		return nil, fmt.Errorf("%w: %v", ErrListUsersFailed, err)
	}

	s.userLogger.Info("Successfully listed users by role", "role", roleStr, "count", len(users))
	return users, nil
}

// ListAllUsers retrieves all users (consider pagination for production).
func (s *UserService) ListAllUsers(ctx context.Context /*, pagination params */) ([]*user.User, error) {
	s.userLogger.Info("Attempting to list all users")
	// TODO: Add pagination parameters (e.g., limit, offset) and pass them to the repository.

	users, err := s.userRepo.ListAll(ctx /*, pagination params */)
	if err != nil {
		s.userLogger.Error("Failed to list all users", "error", err)
		return nil, fmt.Errorf("%w: %v", ErrListUsersFailed, err)
	}

	s.userLogger.Info("Successfully listed all users", "count", len(users))
	return users, nil
}
