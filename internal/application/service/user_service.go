// internal/application/service/user_service.go
package service

import (
	"context"
	"errors"
	"fmt"
	"log"
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
	userRepo   user.UserRepository // This field holds the injected gormUserRepository instance
	userLogger *log.Logger         // TODO: Replace with a structured logger interface
}

// NewUserService creates a new UserService instance.
func NewUserService(userRepo user.UserRepository, userLogger *log.Logger) *UserService {
	if userRepo == nil {
		panic("userRepository is required for UserService")
	}
	if userLogger == nil {
		userLogger = log.Default()
		userLogger.Println("WARN: No logger provided to UserService, using default log package.")
	}
	return &UserService{
		userRepo:   userRepo,
		userLogger: userLogger,
	}
}

// ---* Service methods *---

// CreateUser ... (implementation exists)
func (s *UserService) CreateUser(ctx context.Context, name, email, plainPassword, roleStr, shopIDStr string) (*user.User, error) {
	s.userLogger.Printf("Attempting to create user with email: %s", email)

	// 1. Check if email already exists
	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		s.userLogger.Printf("ERROR: Failed checking email %s: %v", email, err)
		return nil, ErrUnexpected
	}
	if existing != nil {
		s.userLogger.Printf("WARN: Email %s already exists for user ID %d", email, existing.ID)
		return nil, ErrEmailExists
	}

	// 2. Parse role string to Role type
	userRole, err := user.ParseRole(roleStr)
	if err != nil {
		s.userLogger.Printf("WARN: Invalid role provided '%s': %v", roleStr, err)
		return nil, fmt.Errorf("%w: invalid role '%s'", ErrInvalidInput, roleStr)
	}

	// 3. Convert shopID string to *uint if provided
	var shopIDPtr *uint
	if shopIDStr != "" {
		shopIDUint64, err := strconv.ParseUint(shopIDStr, 10, 32)
		if err != nil {
			s.userLogger.Printf("WARN: Invalid shop ID format provided '%s': %v", shopIDStr, err)
			return nil, fmt.Errorf("%w: invalid shop ID format '%s'", ErrInvalidInput, shopIDStr)
		}
		shopIDUint := uint(shopIDUint64)
		shopIDPtr = &shopIDUint
	}

	// 4. Create new domain user object using the factory function
	newUser, err := user.NewUser(name, email, plainPassword, userRole, shopIDPtr)
	if err != nil {
		s.userLogger.Printf("WARN: Validation failed creating user '%s': %v", email, err)
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	// 5. Persist the user using the repository
	s.userLogger.Printf("INFO: Persisting new user with email: %s, Role: %s", email, userRole.String())
	// =====================================================
	// >>>>>>>>>>>> THE GORM .CREATE CALL HAPPENS RIGHT HERE <<<<<<<<<<<<
	// =====================================================
	// 's.userRepo' holds the gormUserRepository instance injected in main.go.
	// Go calls the Create method implemented by gormUserRepository because
	// that's the concrete type satisfying the user.UserRepository interface.
	err = s.userRepo.Create(ctx, newUser)
	if err != nil {
		s.userLogger.Printf("ERROR: Failed to save user '%s' to repository: %v", email, err)
		return nil, fmt.Errorf("%w: %v", ErrCreateUserFailed, err)
	}

	s.userLogger.Printf("INFO: Successfully created user ID %d with email %s", newUser.ID, newUser.Email)
	return newUser, nil
}

// AuthenticateUser ... (implementation exists)
func (s *UserService) AuthenticateUser(ctx context.Context, email, plainPassword string) (*user.User, error) {
	s.userLogger.Printf("Attempting authentication for email: %s", email)

	// 1. Find user by email using the repository
	foundUser, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Printf("WARN: Authentication failed - user not found: %s", email)
			return nil, ErrAuthentication
		}
		s.userLogger.Printf("ERROR: Failed finding user %s during auth: %v", email, err)
		return nil, ErrUnexpected
	}

	// 2. Check if the user account is active
	if !foundUser.IsActive {
		s.userLogger.Printf("WARN: Authentication failed - user inactive: %s (ID: %d)", email, foundUser.ID)
		return nil, ErrAuthentication
	}

	// 3. Check the password using the domain entity's method
	if !foundUser.CheckPassword(plainPassword) {
		s.userLogger.Printf("WARN: Authentication failed - invalid password for user: %s (ID: %d)", email, foundUser.ID)
		return nil, ErrAuthentication
	}

	// 4. Authentication successful
	s.userLogger.Printf("INFO: Authentication successful for user: %s (ID: %d)", email, foundUser.ID)
	return foundUser, nil
}

// GetUserByID ... (implementation exists)
func (s *UserService) GetUserByID(ctx context.Context, id uint) (*user.User, error) {
	s.userLogger.Printf("Attempting to get user by ID: %d", id)

	// 1. Find user by ID using the repository
	foundUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Printf("INFO: User not found for ID: %d", id)
			return nil, ErrUserNotFound
		}
		s.userLogger.Printf("ERROR: Failed finding user by ID %d: %v", id, err)
		return nil, ErrUnexpected
	}

	// 2. User found, return the domain object
	s.userLogger.Printf("INFO: Successfully retrieved user ID %d", id)
	return foundUser, nil
}

// UpdateUserDetails ... (implementation exists)
func (s *UserService) UpdateUserDetails(ctx context.Context, id uint, name, email string) (*user.User, error) {
	s.userLogger.Printf("Attempting to update details for user ID: %d", id)

	// 1. Fetch the existing user
	currentUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Printf("WARN: Cannot update details - user not found: %d", id)
			return nil, ErrUserNotFound
		}
		s.userLogger.Printf("ERROR: Failed finding user %d for update: %v", id, err)
		return nil, ErrUnexpected
	}

	// 2. Apply changes if inputs are provided
	madeChanges := false

	// Update Name
	if name != "" && currentUser.Name != name {
		s.userLogger.Printf("INFO: Updating name for user ID %d", id)
		currentUser.Name = name
		madeChanges = true
	}

	// Update Email
	normalizedNewEmail := strings.ToLower(strings.TrimSpace(email))
	if normalizedNewEmail != "" && currentUser.Email != normalizedNewEmail {
		s.userLogger.Printf("INFO: Attempting to update email for user ID %d to %s", id, normalizedNewEmail)

		// Check if the new email is already taken by *another* user
		existingUserWithEmail, findErr := s.userRepo.FindByEmail(ctx, normalizedNewEmail)
		if findErr != nil && !errors.Is(findErr, ErrUserNotFound) {
			s.userLogger.Printf("ERROR: Failed checking email existence '%s' during update for user %d: %v", normalizedNewEmail, id, findErr)
			return nil, ErrUnexpected
		}
		if existingUserWithEmail != nil && existingUserWithEmail.ID != currentUser.ID {
			s.userLogger.Printf("WARN: Cannot update email for user ID %d - email '%s' already taken by user ID %d", id, normalizedNewEmail, existingUserWithEmail.ID)
			return nil, ErrEmailExists
		}

		currentUser.Email = normalizedNewEmail
		madeChanges = true
	}

	// 3. Persist changes if any were made
	if !madeChanges {
		s.userLogger.Printf("INFO: No details changed for user ID %d", id)
		return currentUser, nil
	}

	s.userLogger.Printf("INFO: Saving updated details for user ID %d", id)
	err = s.userRepo.Update(ctx, currentUser)
	if err != nil {
		s.userLogger.Printf("ERROR: Failed to save updated details for user ID %d: %v", id, err)
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrUpdateUserFailed, err)
	}

	s.userLogger.Printf("INFO: Successfully updated details for user ID %d", id)
	return currentUser, nil
}

// ChangePassword ... (implementation exists)
func (s *UserService) ChangePassword(ctx context.Context, id uint, oldPassword, newPassword string) error {
	s.userLogger.Printf("Attempting to change password for user ID: %d", id)

	// 1. Fetch the existing user
	currentUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Printf("WARN: Cannot change password - user not found: %d", id)
			return ErrUserNotFound
		}
		s.userLogger.Printf("ERROR: Failed finding user %d for password change: %v", id, err)
		return ErrUnexpected
	}

	// 2. Verify the current (old) password
	if !currentUser.CheckPassword(oldPassword) {
		s.userLogger.Printf("WARN: Invalid current password provided for user ID %d", id)
		return ErrCurrentPassword
	}

	// 3. Set the new password using the domain method
	err = currentUser.SetPassword(newPassword)
	if err != nil {
		s.userLogger.Printf("WARN: Validation failed setting new password for user ID %d: %v", id, err)
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	// 4. Persist the updated user
	s.userLogger.Printf("INFO: Saving new password hash for user ID %d", id)
	err = s.userRepo.Update(ctx, currentUser)
	if err != nil {
		s.userLogger.Printf("ERROR: Failed to save updated password for user ID %d: %v", id, err)
		if errors.Is(err, ErrUserNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("%w: %v", ErrUpdateUserFailed, err)
	}

	s.userLogger.Printf("INFO: Successfully changed password for user ID %d", id)
	return nil
}

// ActivateUser marks a user account as active.
func (s *UserService) ActivateUser(ctx context.Context, id uint) error {
	s.userLogger.Printf("Attempting to activate user ID: %d", id)

	// 1. Fetch the user
	currentUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Printf("WARN: Cannot activate user - user not found: %d", id)
			return ErrUserNotFound
		}
		s.userLogger.Printf("ERROR: Failed finding user %d for activation: %v", id, err)
		return ErrUnexpected
	}

	// 2. Check if already active (idempotency)
	if currentUser.IsActive {
		s.userLogger.Printf("INFO: User ID %d is already active.", id)
		return nil // No change needed
	}

	// 3. Use domain method to activate
	currentUser.Activate() // This also updates the UpdatedAt timestamp

	// 4. Persist the change
	s.userLogger.Printf("INFO: Saving activation status for user ID %d", id)
	err = s.userRepo.Update(ctx, currentUser)
	if err != nil {
		s.userLogger.Printf("ERROR: Failed to save activation status for user ID %d: %v", id, err)
		if errors.Is(err, ErrUserNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("%w: %v", ErrUpdateUserFailed, err)
	}

	s.userLogger.Printf("INFO: Successfully activated user ID %d", id)
	return nil
}

// DeactivateUser marks a user account as inactive.
func (s *UserService) DeactivateUser(ctx context.Context, id uint) error {
	s.userLogger.Printf("Attempting to deactivate user ID: %d", id)

	// 1. Fetch the user
	currentUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Printf("WARN: Cannot deactivate user - user not found: %d", id)
			return ErrUserNotFound
		}
		s.userLogger.Printf("ERROR: Failed finding user %d for deactivation: %v", id, err)
		return ErrUnexpected
	}

	// 2. Check if already inactive (idempotency)
	if !currentUser.IsActive {
		s.userLogger.Printf("INFO: User ID %d is already inactive.", id)
		return nil // No change needed
	}

	// 3. Use domain method to deactivate
	currentUser.Deactivate() // This also updates the UpdatedAt timestamp

	// 4. Persist the change
	s.userLogger.Printf("INFO: Saving deactivation status for user ID %d", id)
	err = s.userRepo.Update(ctx, currentUser)
	if err != nil {
		s.userLogger.Printf("ERROR: Failed to save deactivation status for user ID %d: %v", id, err)
		if errors.Is(err, ErrUserNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("%w: %v", ErrUpdateUserFailed, err)
	}

	s.userLogger.Printf("INFO: Successfully deactivated user ID %d", id)
	return nil
}

// DeleteUser removes a user from the system.
// This typically performs a soft delete if the repository is configured for it.
func (s *UserService) DeleteUser(ctx context.Context, id uint) error {
	s.userLogger.Printf("Attempting to delete user ID: %d", id)

	// Directly call the repository's Delete method.
	// The repository handles mapping ErrUserNotFound if the user doesn't exist.
	err := s.userRepo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.userLogger.Printf("WARN: Cannot delete user - user not found: %d", id)
			return ErrUserNotFound
		}
		// Handle other potential repository errors
		s.userLogger.Printf("ERROR: Failed to delete user ID %d: %v", id, err)
		return fmt.Errorf("%w: %v", ErrDeleteUserFailed, err)
	}

	s.userLogger.Printf("INFO: Successfully deleted user ID %d", id)
	return nil
}

// ListUsersByShop retrieves users associated with a specific shop.
func (s *UserService) ListUsersByShop(ctx context.Context, shopID uint) ([]*user.User, error) {
	s.userLogger.Printf("Attempting to list users for shop ID: %d", shopID)

	users, err := s.userRepo.ListByShop(ctx, shopID)
	if err != nil {
		s.userLogger.Printf("ERROR: Failed to list users for shop ID %d: %v", shopID, err)
		// Wrap the error
		return nil, fmt.Errorf("%w: %v", ErrListUsersFailed, err)
	}

	s.userLogger.Printf("INFO: Retrieved %d users for shop ID %d", len(users), shopID)
	return users, nil
}

// ListUsersByRole retrieves users with a specific role.
func (s *UserService) ListUsersByRole(ctx context.Context, role user.Role) ([]*user.User, error) {
	roleStr := role.String()
	s.userLogger.Printf("Attempting to list users with role: %s", roleStr)

	// Validate role just in case (though usually handled at input)
	if !role.IsValidRole() {
		err := fmt.Errorf("%w: invalid role '%s'", ErrInvalidInput, roleStr)
		s.userLogger.Printf("WARN: %v", err)
		return nil, err
	}

	users, err := s.userRepo.ListByRole(ctx, role)
	if err != nil {
		s.userLogger.Printf("ERROR: Failed to list users for role %s: %v", roleStr, err)
		return nil, fmt.Errorf("%w: %v", ErrListUsersFailed, err)
	}

	s.userLogger.Printf("INFO: Retrieved %d users with role %s", len(users), roleStr)
	return users, nil
}

// ListAllUsers retrieves all users (consider pagination for production).
func (s *UserService) ListAllUsers(ctx context.Context /*, pagination params */) ([]*user.User, error) {
	s.userLogger.Println("Attempting to list all users")
	// TODO: Add pagination parameters (e.g., limit, offset) and pass them to the repository.

	users, err := s.userRepo.ListAll(ctx /*, pagination params */)
	if err != nil {
		s.userLogger.Printf("ERROR: Failed to list all users: %v", err)
		return nil, fmt.Errorf("%w: %v", ErrListUsersFailed, err)
	}

	s.userLogger.Printf("INFO: Retrieved %d total users", len(users))
	return users, nil
}
