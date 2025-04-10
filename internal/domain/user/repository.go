package user

import "context"

// UserRepository defines the methods required for user data persistence.
// The implementation will be in the infrastructure layer.
type UserRepository interface {
	// Create saves a new user to the persistence layer.
	// It should update the user's ID, CreatedAt, UpdatedAt upon successful creation.
	Create(ctx context.Context, user *User) error

	// FindByID retrieves a user by their unique ID.
	// Should return an error (e.g., ErrNotFound from pkg/apperrors) if not found.
	FindByID(ctx context.Context, id uint) (*User, error)

	// FindByEmail retrieves a user by their unique email address.
	// Should return an error (e.g., ErrNotFound) if not found.
	FindByEmail(ctx context.Context, email string) (*User, error)

	// Update saves changes to an existing user.
	// Should check for optimistic locking or use the UpdatedAt field if necessary.
	Update(ctx context.Context, user *User) error

	// Delete removes a user by ID (or marks as inactive if using soft deletes).
	Delete(ctx context.Context, id uint) error

	// ListByShop retrieves all users associated with a specific shop ID.
	// (Will typically return ShopManagers and Employees).
	ListByShop(ctx context.Context, shopID uint) ([]*User, error)

	// ListByRole retrieves all users with a specific role.
	ListByRole(ctx context.Context, role Role) ([]*User, error)

	// ListAll retrieves all users (use with caution, consider pagination).
	// Primarily for Admin use cases.
	ListAll(ctx context.Context /*, pagination params */) ([]*User, error)
}
