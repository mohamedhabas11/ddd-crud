// internal/infrastructure/web/dto/user_dto.go
package dto

import (
	"time"

	"github.com/mohamedhabas11/ddd-crud/internal/domain/user"
)

// --- Request DTOs ---

// CreateUserRequest defines the expected JSON body for creating a user.
type CreateUserRequest struct {
	Name     string `json:"name" validate:"required,min=2,max=50"` // Example validation tags
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Role     string `json:"role" validate:"required"` // Role as string (e.g., "Customer", "ShopManager")
	ShopID   string `json:"shop_id,omitempty"`        // ShopID as string, optional
}

// UpdateUserDetailsRequest defines the expected JSON body for updating user details.
// Use pointers or omitempty to indicate optional fields.
type UpdateUserDetailsRequest struct {
	Name  *string `json:"name,omitempty" validate:"omitempty,min=2,max=50"`
	Email *string `json:"email,omitempty" validate:"omitempty,email"`
	// Role and ShopID changes might require specific admin endpoints/logic
}

// ChangePasswordRequest defines the expected JSON body for changing a password.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

// LoginRequest defines the expected JSON body for user login.
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// --- Response DTOs ---

// UserResponse defines the standard JSON representation of a user returned by the API.
// It omits sensitive information like the password hash.
type UserResponse struct {
	ID        uint      `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Role      string    `json:"role"` // Role as string
	ShopID    *uint     `json:"shop_id,omitempty"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuthResponse defines the JSON response after successful login.
type AuthResponse struct {
	User  *UserResponse `json:"user"`
	Token string        `json:"token"` // The JWT
}

// --- Mapping Functions (Domain -> DTO) ---

// ToUserResponse converts a domain user object to its API representation.
func ToUserResponse(domainUser *user.User) *UserResponse {
	if domainUser == nil {
		return nil
	}
	return &UserResponse{
		ID:        domainUser.ID,
		Name:      domainUser.Name,
		Email:     domainUser.Email,
		Role:      domainUser.Role.String(), // Convert Role enum to string
		ShopID:    domainUser.ShopID,
		IsActive:  domainUser.IsActive,
		CreatedAt: domainUser.CreatedAt,
		UpdatedAt: domainUser.UpdatedAt,
	}
}

// ToUserResponseSlice converts a slice of domain users to a slice of API representations.
func ToUserResponseSlice(domainUsers []*user.User) []*UserResponse {
	responses := make([]*UserResponse, len(domainUsers))
	for i, u := range domainUsers {
		responses[i] = ToUserResponse(u)
	}
	return responses
}
