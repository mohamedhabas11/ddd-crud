// internal/infrastructure/security/jwt.go
package security

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mohamedhabas11/ddd-crud/internal/domain/user" // For user.Role
)

// ErrTokenInvalid indicates a malformed or invalid token.
var ErrTokenInvalid = errors.New("token is invalid")

// ErrTokenExpired indicates the token has passed its expiry time.
var ErrTokenExpired = errors.New("token has expired")

// Claims defines the structure of the JWT claims, including custom ones.
type Claims struct {
	UserID uint      `json:"user_id"`
	Role   user.Role `json:"role"`
	jwt.RegisteredClaims
}

// JWTService handles JWT generation and validation.
type JWTService struct {
	secretKey      []byte
	expireDuration time.Duration
}

// NewJWTService creates a new JWTService instance.
func NewJWTService(secret string, expireMinutes int) (*JWTService, error) {
	if secret == "" {
		return nil, errors.New("JWT secret cannot be empty")
	}
	if expireMinutes <= 0 {
		expireMinutes = 60 // Default to 60 minutes if invalid
	}
	return &JWTService{
		secretKey:      []byte(secret),
		expireDuration: time.Duration(expireMinutes) * time.Minute,
	}, nil
}

// GenerateToken creates a new JWT for a given user ID and role.
func (s *JWTService) GenerateToken(userID uint, role user.Role) (string, error) {
	if userID == 0 {
		return "", errors.New("cannot generate token for zero user ID")
	}

	// Create the claims
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.expireDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%d", userID), // Subject is typically the user ID as a string
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken parses and validates a JWT string.
// Returns the claims if the token is valid, otherwise returns an error.
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret key for validation
		return s.secretKey, nil
	})

	if err != nil {
		// Handle specific JWT errors
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, ErrTokenInvalid
		}
		// Handle other parsing errors (e.g., signature invalid)
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	// Check if the token is valid and extract claims
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Optional: Add further checks here if needed (e.g., check issuer)
		return claims, nil
	}

	return nil, ErrTokenInvalid // Should not happen if parsing succeeded and token.Valid is true
}
