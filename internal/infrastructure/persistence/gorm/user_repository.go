// internal/infrastructure/persistence/gorm/user_repository.go
package gorm

import (
	"context"
	"errors"
	"fmt"
	"log/slog" // <--- CHANGE THIS IMPORT (if you had "log")

	"github.com/mohamedhabas11/ddd-crud/internal/application/service"
	"github.com/mohamedhabas11/ddd-crud/internal/domain/user"

	"gorm.io/gorm"
)

// gormUserRepository implements the user.UserRepository interface using GORM.
type gormUserRepository struct {
	db     *gorm.DB
	logger *slog.Logger // <--- CHANGE THIS FIELD TYPE
}

// NewGormUserRepository creates a new GORM user repository instance.
// CHANGE the parameter type here:
func NewGormUserRepository(db *gorm.DB, logger *slog.Logger) user.UserRepository {
	if db == nil {
		panic("database connection (*gorm.DB) is required for GormUserRepository")
	}
	if logger == nil {
		// It's better practice to ensure main always provides a logger,
		// but if you need a default:
		logger = slog.Default() // Use slog's default
		logger.Warn("No logger provided to GormUserRepository, using default slog logger.")
	}
	return &gormUserRepository{
		db:     db,
		logger: logger, // Assign the slog logger
	}
}

// --- Interface Implementation ---

// Create saves a new user to the database.
func (r *gormUserRepository) Create(ctx context.Context, domainUser *user.User) error {
	gormUser := fromDomain(domainUser)
	if gormUser == nil {
		// Use slog for logging
		r.logger.Error("Attempted to create user from nil domain object")
		return errors.New("cannot create user from nil domain object")
	}

	// Use slog structured logging
	r.logger.Debug("Attempting to create GormUser", "email", gormUser.Email)

	result := r.db.WithContext(ctx).Create(gormUser)
	if result.Error != nil {
		// Use slog structured logging
		r.logger.Error("Failed to create user in DB", "email", domainUser.Email, "error", result.Error)
		return fmt.Errorf("database error during user creation: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Error("No rows affected when creating user", "email", domainUser.Email, "db_error", result.Error) // Include original error if available
		return errors.New("user creation failed in database, no rows affected")
	}

	// Update the original domain user with DB-generated fields
	domainUser.ID = gormUser.ID
	domainUser.CreatedAt = gormUser.CreatedAt
	domainUser.UpdatedAt = gormUser.UpdatedAt

	r.logger.Info("Successfully created user", "user_id", domainUser.ID, "email", domainUser.Email)
	return nil
}

// FindByID retrieves a user by their unique ID.
func (r *gormUserRepository) FindByID(ctx context.Context, id uint) (*user.User, error) {
	var gormUser GormUser
	r.logger.Debug("Querying for user by ID", "user_id", id)

	result := r.db.WithContext(ctx).First(&gormUser, id)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			r.logger.Info("User not found for ID", "user_id", id)
			return nil, service.ErrUserNotFound // Map to application error
		}
		r.logger.Error("Database error finding user by ID", "user_id", id, "error", result.Error)
		return nil, fmt.Errorf("database error finding user by ID: %w", result.Error)
	}

	r.logger.Debug("Found user, mapping to domain", "user_id", gormUser.ID)
	return toDomain(&gormUser), nil
}

// FindByEmail retrieves a user by their unique email address.
func (r *gormUserRepository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	var gormUser GormUser
	r.logger.Debug("Querying for user by email", "email", email)

	result := r.db.WithContext(ctx).Where("email = ?", email).First(&gormUser)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			r.logger.Info("User not found for email", "email", email)
			return nil, service.ErrUserNotFound // Map to application error
		}
		r.logger.Error("Database error finding user by email", "email", email, "error", result.Error)
		return nil, fmt.Errorf("database error finding user by email: %w", result.Error)
	}

	r.logger.Debug("Found user, mapping to domain", "email", gormUser.Email, "user_id", gormUser.ID)
	return toDomain(&gormUser), nil
}

// Update saves changes to an existing user using GORM's Save method.
func (r *gormUserRepository) Update(ctx context.Context, domainUser *user.User) error {
	if domainUser.ID == 0 {
		r.logger.Error("Attempted to update user with ID 0")
		return errors.New("cannot update user with zero ID")
	}

	gormUser := fromDomain(domainUser)
	if gormUser == nil {
		r.logger.Error("Attempted to update user from nil domain object")
		return errors.New("cannot update user from nil domain object")
	}

	r.logger.Debug("Attempting to update GormUser", "user_id", gormUser.ID)

	result := r.db.WithContext(ctx).Save(gormUser)
	if result.Error != nil {
		r.logger.Error("Failed to update user in DB", "user_id", domainUser.ID, "error", result.Error)
		return fmt.Errorf("database error during user update: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Warn("Update affected 0 rows (user likely not found)", "user_id", domainUser.ID)
		return service.ErrUserNotFound // Map to application error
	}

	domainUser.UpdatedAt = gormUser.UpdatedAt

	r.logger.Info("Successfully updated user", "user_id", domainUser.ID)
	return nil
}

// Delete removes a user by ID (soft or hard depending on GormUser model).
func (r *gormUserRepository) Delete(ctx context.Context, id uint) error {
	if id == 0 {
		r.logger.Error("Attempted to delete user with ID 0")
		return errors.New("cannot delete user with zero ID")
	}
	r.logger.Debug("Attempting to delete user by ID", "user_id", id)

	result := r.db.WithContext(ctx).Delete(&GormUser{}, id)

	if result.Error != nil {
		r.logger.Error("Failed to delete user from DB", "user_id", id, "error", result.Error)
		return fmt.Errorf("database error during user deletion: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Warn("Delete affected 0 rows (user likely not found)", "user_id", id)
		return service.ErrUserNotFound // Map to application error
	}

	r.logger.Info("Successfully deleted (or soft-deleted) user", "user_id", id)
	return nil
}

// ListByShop retrieves all users associated with a specific shop ID.
func (r *gormUserRepository) ListByShop(ctx context.Context, shopID uint) ([]*user.User, error) {
	var gormUsers []GormUser
	r.logger.Debug("Querying for users by shop ID", "shop_id", shopID)

	result := r.db.WithContext(ctx).Where("shop_id = ?", shopID).Find(&gormUsers)
	if result.Error != nil {
		r.logger.Error("Database error listing users by shop ID", "shop_id", shopID, "error", result.Error)
		return nil, fmt.Errorf("database error listing users by shop: %w", result.Error)
	}

	r.logger.Debug("Found users for shop", "shop_id", shopID, "count", len(gormUsers))
	return toDomainSlice(gormUsers), nil
}

// ListByRole retrieves all users with a specific role.
func (r *gormUserRepository) ListByRole(ctx context.Context, role user.Role) ([]*user.User, error) {
	var gormUsers []GormUser
	roleStr := role.String()
	r.logger.Debug("Querying for users by role", "role", roleStr, "role_int", role)

	result := r.db.WithContext(ctx).Where("role = ?", role).Find(&gormUsers)
	if result.Error != nil {
		r.logger.Error("Database error listing users by role", "role", roleStr, "error", result.Error)
		return nil, fmt.Errorf("database error listing users by role: %w", result.Error)
	}

	r.logger.Debug("Found users for role", "role", roleStr, "count", len(gormUsers))
	return toDomainSlice(gormUsers), nil
}

// ListAll retrieves all users. Implement pagination for production use.
func (r *gormUserRepository) ListAll(ctx context.Context /*, pagination params */) ([]*user.User, error) {
	var gormUsers []GormUser
	r.logger.Debug("Querying for all users")

	// TODO: Add Limit/Offset for pagination.
	result := r.db.WithContext(ctx).Find(&gormUsers)
	if result.Error != nil {
		r.logger.Error("Database error listing all users", "error", result.Error)
		return nil, fmt.Errorf("database error listing all users: %w", result.Error)
	}

	r.logger.Debug("Found total users", "count", len(gormUsers))
	return toDomainSlice(gormUsers), nil
}
