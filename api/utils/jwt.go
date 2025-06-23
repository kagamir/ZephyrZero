package utils

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTClaims struct {
	UserID    uint   `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"` // access, refresh
	jwt.RegisteredClaims
}

type JWTManager struct {
	secretKey            []byte
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

func NewJWTManager(secretKey string, accessDuration, refreshDuration time.Duration) *JWTManager {
	return &JWTManager{
		secretKey:            []byte(secretKey),
		accessTokenDuration:  accessDuration,
		refreshTokenDuration: refreshDuration,
	}
}

// GenerateAccessToken generates access token
func (j *JWTManager) GenerateAccessToken(userID uint, username, role string) (string, error) {
	claims := &JWTClaims{
		UserID:    userID,
		Username:  username,
		Role:      role,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.accessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "zephyr-zero-file-storage",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// GenerateRefreshToken generates refresh token
func (j *JWTManager) GenerateRefreshToken(userID uint, username, role string) (string, error) {
	claims := &JWTClaims{
		UserID:    userID,
		Username:  username,
		Role:      role,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.refreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "zephyr-zero-file-storage",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// ValidateToken validates token
func (j *JWTManager) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// ExtractClaimsFromToken extracts claims from token (without validation)
func (j *JWTManager) ExtractClaimsFromToken(tokenString string) (*JWTClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &JWTClaims{})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok {
		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}

// IsTokenExpired checks if token is expired
func (j *JWTManager) IsTokenExpired(tokenString string) bool {
	claims, err := j.ExtractClaimsFromToken(tokenString)
	if err != nil {
		return true
	}

	return time.Now().After(claims.ExpiresAt.Time)
}

// GetTokenRemainingTime gets token remaining time
func (j *JWTManager) GetTokenRemainingTime(tokenString string) (time.Duration, error) {
	claims, err := j.ExtractClaimsFromToken(tokenString)
	if err != nil {
		return 0, err
	}

	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining < 0 {
		return 0, errors.New("token expired")
	}

	return remaining, nil
}

// RefreshAccessToken uses refresh token to generate new access token
func (j *JWTManager) RefreshAccessToken(refreshToken string) (string, error) {
	// Validate refresh token
	claims, err := j.ValidateToken(refreshToken)
	if err != nil {
		return "", err
	}

	// Check token type
	if claims.TokenType != "refresh" {
		return "", errors.New("invalid token type")
	}

	// Generate new access token
	return j.GenerateAccessToken(claims.UserID, claims.Username, claims.Role)
}

// GenerateTokenPair generates access and refresh token pair
func (j *JWTManager) GenerateTokenPair(userID uint, username, role string) (accessToken, refreshToken string, err error) {
	accessToken, err = j.GenerateAccessToken(userID, username, role)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = j.GenerateRefreshToken(userID, username, role)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
