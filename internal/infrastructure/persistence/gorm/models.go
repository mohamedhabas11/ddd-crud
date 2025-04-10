// internal/infrastructure/persistence/gorm/models.go
package gorm

import (

	// Import the domain user package to use the Role type and User entity
	"github.com/mohamedhabas11/ddd-crud/internal/domain/user"

	"gorm.io/gorm" // Import GORM
)

// GormUser is the database representation of the User entity.
// It includes GORM-specific fields and tags.
type GormUser struct {
	gorm.Model // Embeds ID (uint), CreatedAt, UpdatedAt, DeletedAt

	Name         string    `gorm:"type:varchar(100);not null"`             // Example size
	Email        string    `gorm:"type:varchar(254);uniqueIndex;not null"` // Standard email length, unique index
	PasswordHash string    `gorm:"type:varchar(255);not null"`             // Store the hash
	Role         user.Role `gorm:"type:smallint;not null"`                 // Store Role as a small integer
	ShopID       *uint     `gorm:"index"`                                  // Nullable uint, add index for faster lookups
	IsActive     bool      `gorm:"default:true;not null"`                  // Default to true
}

// TableName specifies the table name for the GormUser model.
func (GormUser) TableName() string {
	return "users" // Explicitly set table name
}

// --- Mapping Functions ---

// toDomain converts a GormUser database model to a user.User domain entity.
// It maps the fields from the GORM struct to the domain struct.
func toDomain(gormUser *GormUser) *user.User {
	if gormUser == nil {
		return nil
	}
	return &user.User{
		ID:           gormUser.ID,
		Name:         gormUser.Name,
		Email:        gormUser.Email,
		PasswordHash: gormUser.PasswordHash,
		Role:         gormUser.Role,
		ShopID:       gormUser.ShopID, // Directly assign the pointer
		IsActive:     gormUser.IsActive,
		CreatedAt:    gormUser.CreatedAt,
		UpdatedAt:    gormUser.UpdatedAt,
		// Note: Domain User does not have DeletedAt
	}
}

// fromDomain converts a user.User domain entity to a GormUser database model.
// It prepares the data for saving or updating in the database via GORM.
func fromDomain(domainUser *user.User) *GormUser {
	if domainUser == nil {
		return nil
	}
	gormUser := &GormUser{
		Name:         domainUser.Name,
		Email:        domainUser.Email,
		PasswordHash: domainUser.PasswordHash,
		Role:         domainUser.Role,
		ShopID:       domainUser.ShopID, // Directly assign the pointer
		IsActive:     domainUser.IsActive,
		// Let GORM handle ID, CreatedAt, UpdatedAt, DeletedAt automatically
		// when creating. For updates, we need the ID.
	}
	// Important: If the domain user has an ID (meaning it likely exists),
	// set it on the GormUser model so GORM knows which record to update.
	if domainUser.ID != 0 {
		gormUser.ID = domainUser.ID
		// We also copy CreatedAt to prevent GORM from trying to update it on .Save()
		// GORM typically only auto-updates UpdatedAt on .Save() or .Updates()
		// but setting CreatedAt ensures it remains unchanged.
		gormUser.CreatedAt = domainUser.CreatedAt
		// GORM will automatically handle UpdatedAt on save/update.
	}

	return gormUser
}

// Helper function to convert a slice of GormUser to a slice of domain User
func toDomainSlice(gormUsers []GormUser) []*user.User {
	domainUsers := make([]*user.User, len(gormUsers))
	for i, gu := range gormUsers {
		// Need to take the address of the loop variable copy
		// or use the index to access the original slice element's address
		// to avoid capturing the same pointer in each iteration.
		// Easiest is often to call toDomain with the element directly.
		// domainUsers[i] = toDomain(&gormUsers[i])
		domainUsers[i] = toDomain(&gu)
	}
	return domainUsers
}
