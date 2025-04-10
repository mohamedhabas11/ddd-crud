// internal/infrastructure/persistence/gorm/user_repository.go
package gorm

import (
	"context"
	"errors"
	"fmt"
	"log" // TODO: Replace with a proper structured logger interface

	"github.com/mohamedhabas11/ddd-crud/internal/application/service" // For application errors like ErrUserNotFound
	"github.com/mohamedhabas11/ddd-crud/internal/domain/user"

	"gorm.io/gorm"
)

// gormUserRepository implements the user.UserRepository interface using GORM.
// This implementation aims to be database-agnostic between PostgreSQL and MySQL/MariaDB
// by relying on GORM abstractions and avoiding DB-specific error codes.
type gormUserRepository struct {
	db     *gorm.DB
	logger *log.Logger
}

// NewGormUserRepository creates a new GORM user repository instance.
func NewGormUserRepository(db *gorm.DB, logger *log.Logger) user.UserRepository {
	if db == nil {
		panic("database connection (*gorm.DB) is required for GormUserRepository")
	}
	if logger == nil {
		logger = log.Default()
		logger.Println("WARN: No logger provided to GormUserRepository, using default log package.")
	}
	return &gormUserRepository{
		db:     db,
		logger: logger,
	}
}

// --- Interface Implementation ---

// Create saves a new user to the database.
func (r *gormUserRepository) Create(ctx context.Context, domainUser *user.User) error {
	gormUser := fromDomain(domainUser)
	if gormUser == nil {
		r.logger.Println("ERROR: Attempted to create user from nil domain object")
		return errors.New("cannot create user from nil domain object")
	}

	r.logger.Printf("DEBUG: Attempting to create GormUser for email: %s", gormUser.Email)

	result := r.db.WithContext(ctx).Create(gormUser)
	if result.Error != nil {
		r.logger.Printf("ERROR: Failed to create user '%s' in DB: %v", domainUser.Email, result.Error)

		// --- Portability Adjustment ---
		// REMOVED: Database-specific error checks (like checking pgconn.PgError code 23505).
		// Rely on the service layer's pre-check (FindByEmail) for handling existing emails portably.
		// If a unique constraint is violated here, GORM returns a generic error.
		// We wrap it to provide context without being DB-specific.
		// The service layer might interpret this wrapped error generically or rely on its pre-check.
		return fmt.Errorf("database error during user creation: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Printf("ERROR: No rows affected when creating user: %s (DB Error: %v)", domainUser.Email, result.Error)
		return errors.New("user creation failed in database, no rows affected")
	}

	// Update the original domain user with DB-generated fields
	domainUser.ID = gormUser.ID
	domainUser.CreatedAt = gormUser.CreatedAt
	domainUser.UpdatedAt = gormUser.UpdatedAt

	r.logger.Printf("INFO: Successfully created user ID %d with email %s", domainUser.ID, domainUser.Email)
	return nil
}

// FindByID retrieves a user by their unique ID.
func (r *gormUserRepository) FindByID(ctx context.Context, id uint) (*user.User, error) {
	var gormUser GormUser
	r.logger.Printf("DEBUG: Querying for user by ID: %d", id)

	result := r.db.WithContext(ctx).First(&gormUser, id)

	if result.Error != nil {
		// gorm.ErrRecordNotFound is a GORM-level error, portable across dialects.
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			r.logger.Printf("INFO: User not found for ID: %d", id)
			return nil, service.ErrUserNotFound // Map to application error
		}
		// Other DB errors
		r.logger.Printf("ERROR: Database error finding user by ID %d: %v", id, result.Error)
		return nil, fmt.Errorf("database error finding user by ID: %w", result.Error)
	}

	r.logger.Printf("DEBUG: Found user ID %d, mapping to domain.", gormUser.ID)
	return toDomain(&gormUser), nil
}

// FindByEmail retrieves a user by their unique email address.
func (r *gormUserRepository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	var gormUser GormUser
	r.logger.Printf("DEBUG: Querying for user by email: %s", email)

	result := r.db.WithContext(ctx).Where("email = ?", email).First(&gormUser)

	if result.Error != nil {
		// gorm.ErrRecordNotFound is portable.
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			r.logger.Printf("INFO: User not found for email: %s", email)
			return nil, service.ErrUserNotFound // Map to application error
		}
		// Other DB errors
		r.logger.Printf("ERROR: Database error finding user by email %s: %v", email, result.Error)
		return nil, fmt.Errorf("database error finding user by email: %w", result.Error)
	}

	r.logger.Printf("DEBUG: Found user email %s (ID: %d), mapping to domain.", gormUser.Email, gormUser.ID)
	return toDomain(&gormUser), nil
}

// Update saves changes to an existing user using GORM's Save method.
func (r *gormUserRepository) Update(ctx context.Context, domainUser *user.User) error {
	if domainUser.ID == 0 {
		r.logger.Println("ERROR: Attempted to update user with ID 0")
		return errors.New("cannot update user with zero ID")
	}

	gormUser := fromDomain(domainUser)
	if gormUser == nil {
		r.logger.Println("ERROR: Attempted to update user from nil domain object")
		return errors.New("cannot update user from nil domain object")
	}

	r.logger.Printf("DEBUG: Attempting to update GormUser ID: %d", gormUser.ID)

	// GORM's Save is generally portable.
	result := r.db.WithContext(ctx).Save(gormUser)
	if result.Error != nil {
		r.logger.Printf("ERROR: Failed to update user ID %d in DB: %v", domainUser.ID, result.Error)
		// --- Portability Adjustment ---
		// REMOVED: Database-specific error checks (e.g., for unique constraint violations on email update).
		// Rely on service layer pre-checks if specific errors need handling before update.
		return fmt.Errorf("database error during user update: %w", result.Error)
	}

	// Checking RowsAffected == 0 after Save is a portable way to detect if the record existed.
	if result.RowsAffected == 0 {
		r.logger.Printf("WARN: Update for user ID %d affected 0 rows (user likely not found).", domainUser.ID)
		return service.ErrUserNotFound // Map to application error
	}

	// Update the original domain user with the new UpdatedAt
	domainUser.UpdatedAt = gormUser.UpdatedAt

	r.logger.Printf("INFO: Successfully updated user ID %d", domainUser.ID)
	return nil
}

// Delete removes a user by ID (soft or hard depending on GormUser model).
func (r *gormUserRepository) Delete(ctx context.Context, id uint) error {
	if id == 0 {
		r.logger.Println("ERROR: Attempted to delete user with ID 0")
		return errors.New("cannot delete user with zero ID")
	}
	r.logger.Printf("DEBUG: Attempting to delete user by ID: %d", id)

	// GORM's Delete using a model and ID is portable.
	result := r.db.WithContext(ctx).Delete(&GormUser{}, id)

	if result.Error != nil {
		r.logger.Printf("ERROR: Failed to delete user ID %d from DB: %v", id, result.Error)
		return fmt.Errorf("database error during user deletion: %w", result.Error)
	}

	// Checking RowsAffected == 0 is a portable way to detect if the record existed.
	if result.RowsAffected == 0 {
		r.logger.Printf("WARN: Delete for user ID %d affected 0 rows (user likely not found).", id)
		return service.ErrUserNotFound // Map to application error
	}

	r.logger.Printf("INFO: Successfully deleted (or soft-deleted) user ID %d", id)
	return nil
}

// ListByShop retrieves all users associated with a specific shop ID.
func (r *gormUserRepository) ListByShop(ctx context.Context, shopID uint) ([]*user.User, error) {
	var gormUsers []GormUser
	r.logger.Printf("DEBUG: Querying for users by shop ID: %d", shopID)

	// GORM's Where and Find are portable.
	result := r.db.WithContext(ctx).Where("shop_id = ?", shopID).Find(&gormUsers)
	if result.Error != nil {
		r.logger.Printf("ERROR: Database error listing users by shop ID %d: %v", shopID, result.Error)
		return nil, fmt.Errorf("database error listing users by shop: %w", result.Error)
	}

	r.logger.Printf("DEBUG: Found %d users for shop ID %d", len(gormUsers), shopID)
	return toDomainSlice(gormUsers), nil
}

// ListByRole retrieves all users with a specific role.
func (r *gormUserRepository) ListByRole(ctx context.Context, role user.Role) ([]*user.User, error) {
	var gormUsers []GormUser
	roleStr := role.String()
	r.logger.Printf("DEBUG: Querying for users by role: %s (%d)", roleStr, role)

	// GORM's Where and Find are portable.
	result := r.db.WithContext(ctx).Where("role = ?", role).Find(&gormUsers)
	if result.Error != nil {
		r.logger.Printf("ERROR: Database error listing users by role %s: %v", roleStr, result.Error)
		return nil, fmt.Errorf("database error listing users by role: %w", result.Error)
	}

	r.logger.Printf("DEBUG: Found %d users for role %s", len(gormUsers), roleStr)
	return toDomainSlice(gormUsers), nil
}

// ListAll retrieves all users. Implement pagination for production use.
func (r *gormUserRepository) ListAll(ctx context.Context /*, pagination params */) ([]*user.User, error) {
	var gormUsers []GormUser
	r.logger.Println("DEBUG: Querying for all users")

	// GORM's Find is portable. Add Limit/Offset for pagination.
	result := r.db.WithContext(ctx).Find(&gormUsers)
	if result.Error != nil {
		r.logger.Printf("ERROR: Database error listing all users: %v", result.Error)
		return nil, fmt.Errorf("database error listing all users: %w", result.Error)
	}

	r.logger.Printf("DEBUG: Found %d total users", len(gormUsers))
	return toDomainSlice(gormUsers), nil
}
