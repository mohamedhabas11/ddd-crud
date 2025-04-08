package user

import (
	"errors"
	"fmt"
	"net/mail"
	"time"
	"unicode/utf8" // For more robust name length check

	"golang.org/x/crypto/bcrypt"
	// NO gorm import here!
)

// ---* Error constants *---
var (
	ErrNameLength        = fmt.Errorf("name must be between %d and %d characters", MinNameLength, MaxNameLength)
	ErrPasswordLength    = fmt.Errorf("password must be at least %d characters", MinPasswordLength) // Max length often handled by bcrypt limit implicitly
	ErrInvalidEmail      = errors.New("invalid email format")
	ErrInvalidRole       = errors.New("invalid role specified")
	ErrHashingPassword   = errors.New("failed to hash password")
	ErrAdminHasShopID    = errors.New("admin users cannot be assigned to a shop")
	ErrCustomerHasShopID = errors.New("customer users cannot be assigned to a shop")
	ErrMissingShopID     = errors.New("shop owners and employees must be assigned to a shop")
)

// ---* Validation constants *---
const (
	MinPasswordLength = 8
	// MaxPasswordLength = 72 // bcrypt has a limit of 72 bytes, often not explicitly checked here
	MinNameLength  = 2
	MaxNameLength  = 50  // Adjusted max length
	MaxEmailLength = 254 // Standard email length limit
)

// User represents a user in the system (Domain Entity).
// It is independent of storage mechanisms (like GORM).
type User struct {
	ID           uint      `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"` // Should be unique (enforced by infrastructure)
	PasswordHash string    `json:"-"`     // Store only the hash
	Role         Role      `json:"role"`
	ShopID       *uint     `json:"shop_id,omitempty"` // Pointer to allow NULL
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	// No DeletedAt here - that's a persistence concern
}

// NewUser is a factory function to create a new valid User instance.
// It handles validation and password hashing during creation.
func NewUser(name, email, plainPassword string, role Role, shopID *uint) (*User, error) {
	// Validate Inputs
	if err := validateName(name); err != nil {
		return nil, err
	}
	if err := validateEmail(email); err != nil {
		return nil, err
	}
	if err := validatePassword(plainPassword); err != nil {
		return nil, err
	}
	if !role.IsValidRole() {
		return nil, ErrInvalidRole
	}

	// Role-specific ShopID validation
	switch role {
	case RoleAdmin:
		if shopID != nil {
			return nil, ErrAdminHasShopID
		}
	case RoleCustomer:
		if shopID != nil {
			return nil, ErrCustomerHasShopID
		}
	case RoleShopOwner, RoleEmployee:
		if shopID == nil {
			// Consider if 0 is a valid shop ID if not using pointers
			return nil, ErrMissingShopID
		}
	}

	// Hash password
	hashedPassword, err := hashPassword(plainPassword)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHashingPassword, err)
	}

	now := time.Now().UTC()
	user := &User{
		Name:         name,
		Email:        email,
		PasswordHash: hashedPassword,
		Role:         role,
		ShopID:       shopID,
		IsActive:     true, // Default to active
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	return user, nil
}

// SetPassword validates and hashes a new password for an existing user.
func (u *User) SetPassword(plainPassword string) error {
	if err := validatePassword(plainPassword); err != nil {
		return err
	}
	hashedPassword, err := hashPassword(plainPassword)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHashingPassword, err)
	}
	u.PasswordHash = hashedPassword
	u.UpdatedAt = time.Now().UTC()
	return nil
}

// CheckPassword compares a plain text password against the user's stored hash.
func (u *User) CheckPassword(plainPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(plainPassword))
	return err == nil // Returns true if password matches, false otherwise
}

// Deactivate marks the user as inactive.
func (u *User) Deactivate() {
	if u.IsActive {
		u.IsActive = false
		u.UpdatedAt = time.Now().UTC()
	}
}

// Activate marks the user as active.
func (u *User) Activate() {
	if !u.IsActive {
		u.IsActive = true
		u.UpdatedAt = time.Now().UTC()
	}
}

// CanManageEmployees checks if the user role allows managing employees.
func (u *User) CanManageEmployees() bool {
	return u.Role == RoleShopOwner
}

// CanManageInventories checks if the user role allows managing inventories.
func (u *User) CanManageInventories() bool {
	return u.Role == RoleShopOwner || u.Role == RoleEmployee
}

// CanPlaceOrders checks if the user role allows placing orders.
func (u *User) CanPlaceOrders() bool {
	return u.Role == RoleCustomer
}

//---* Private validation helpers *---

// validateName checks if the name meets the length requirements.
// Using utf8.RuneCountInString for potentially multi-byte characters.
func validateName(name string) error {
	length := utf8.RuneCountInString(name)
	if length < MinNameLength || length > MaxNameLength {
		return ErrNameLength
	}
	return nil
}

// validateEmail checks if the email has a valid format and length.
func validateEmail(email string) error {
	if len(email) > MaxEmailLength {
		return ErrInvalidEmail // Or a specific length error
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return ErrInvalidEmail
	}
	return nil
}

// validatePassword checks if the password meets the minimum length requirement.
func validatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return ErrPasswordLength
	}
	// Note: Max length check often omitted as bcrypt handles it (up to 72 bytes)
	return nil
}

// hashPassword hashes a password using bcrypt.
func hashPassword(password string) (string, error) {
	// bcrypt cost can be configurable
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
