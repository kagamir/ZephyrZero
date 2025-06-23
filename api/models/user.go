package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID         uint   `json:"id" gorm:"primarykey"`
	Username   string `json:"username" gorm:"uniqueIndex;not null" validate:"required,min=3,max=50"`
	Email      string `json:"email" gorm:"uniqueIndex;not null" validate:"required,email"`
	Password   string `json:"-" gorm:"not null"`
	Role       string `json:"role" gorm:"default:user" validate:"oneof=admin user guest"`
	IsActive   bool   `json:"is_active" gorm:"default:true"`
	IsVerified bool   `json:"is_verified" gorm:"default:false"`

	// Zero trust related fields
	MFAEnabled    bool       `json:"mfa_enabled" gorm:"default:false"`
	MFASecret     string     `json:"-" gorm:"column:mfa_secret"`
	LastLoginIP   string     `json:"last_login_ip"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	LoginAttempts int        `json:"-" gorm:"default:0"`
	LockedUntil   *time.Time `json:"-"`

	// Session management
	RefreshToken string     `json:"-"`
	TokenExpiry  *time.Time `json:"-"`

	// Audit fields
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	// Associations
	Files     []File     `json:"files,omitempty" gorm:"foreignKey:UserID"`
	AuditLogs []AuditLog `json:"audit_logs,omitempty" gorm:"foreignKey:UserID"`
}

type LoginRequest struct {
	Username   string `json:"username" validate:"required"`
	Password   string `json:"password" validate:"required,min=8"`
	RememberMe bool   `json:"remember_me"`
	MFACode    string `json:"mfa_code,omitempty"`
}

type RegisterRequest struct {
	Username        string `json:"username" validate:"required,min=3,max=50"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=Password"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword"`
}

type MFASetupRequest struct {
	Password string `json:"password" validate:"required"`
}

type MFAVerifyRequest struct {
	Code string `json:"code" validate:"required,len=6"`
}

type UserResponse struct {
	ID          uint       `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	IsActive    bool       `json:"is_active"`
	IsVerified  bool       `json:"is_verified"`
	MFAEnabled  bool       `json:"mfa_enabled"`
	LastLoginAt *time.Time `json:"last_login_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (u *User) ToResponse() *UserResponse {
	return &UserResponse{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		Role:        u.Role,
		IsActive:    u.IsActive,
		IsVerified:  u.IsVerified,
		MFAEnabled:  u.MFAEnabled,
		LastLoginAt: u.LastLoginAt,
		CreatedAt:   u.CreatedAt,
	}
}

func (u *User) IsAccountLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

func (u *User) CanAttemptLogin() bool {
	return !u.IsAccountLocked() && u.IsActive
}
