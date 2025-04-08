package user

import "fmt"

// Role represents the type of user within the application.
type Role int

const (
	// RoleUndefined is the zero value, should not be used for active users.
	RoleUndefined Role = iota // 0
	// RoleAdmin represents an application administrator.
	RoleAdmin // 1
	// RoleShopOwner represents a user who owns and manages a shop.
	RoleShopOwner // 2
	// RoleEmployee represents a user employed at a shop.
	RoleEmployee // 3
	// RoleCustomer represents a standard customer who can place orders.
	RoleCustomer // 4
)

// String returns the string representation of the Role.
func (r Role) String() string {
	switch r {
	case RoleAdmin:
		return "Admin"
	case RoleShopOwner:
		return "ShopOwner"
	case RoleEmployee:
		return "Employee"
	case RoleCustomer:
		return "Customer"
	default:
		return "Undefined"
	}
}

// IsValidRole checks if the role is a defined, valid role.
func (r Role) IsValidRole() bool {
	switch r {
	case RoleAdmin, RoleShopOwner, RoleEmployee, RoleCustomer:
		return true
	default:
		return false
	}
}

// ParseRole converts a string to a Role. Returns error if invalid.
func ParseRole(s string) (Role, error) {
	switch s {
	case "Admin":
		return RoleAdmin, nil
	case "ShopOwner":
		return RoleShopOwner, nil
	case "Employee":
		return RoleEmployee, nil
	case "Customer":
		return RoleCustomer, nil
	default:
		return RoleUndefined, fmt.Errorf("invalid role string: %q", s)
	}
}
