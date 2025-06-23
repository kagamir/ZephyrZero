package models

import (
	"time"
)

type AuditLog struct {
	ID         uint   `json:"id" gorm:"primarykey"`
	UserID     *uint  `json:"user_id,omitempty" gorm:"index"`
	Action     string `json:"action" gorm:"not null;index"` // login, logout, upload, download, delete, etc.
	Resource   string `json:"resource" gorm:"not null"`     // user, file, system
	ResourceID *uint  `json:"resource_id,omitempty" gorm:"index"`

	// Request information
	Method    string `json:"method"`
	Path      string `json:"path"`
	UserAgent string `json:"user_agent"`
	IPAddress string `json:"ip_address" gorm:"index"`

	// Result information
	Success    bool   `json:"success" gorm:"index"`
	StatusCode int    `json:"status_code"`
	ErrorMsg   string `json:"error_msg,omitempty"`

	// Detailed information
	Details  map[string]interface{} `json:"details,omitempty" gorm:"serializer:json"`
	Duration int64                  `json:"duration"` // milliseconds

	// Risk assessment
	RiskLevel string `json:"risk_level" gorm:"default:low;index"` // low, medium, high, critical

	CreatedAt time.Time `json:"created_at" gorm:"index"`

	// Associations
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

type AuditLogRequest struct {
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID *uint                  `json:"resource_id,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
	RiskLevel  string                 `json:"risk_level,omitempty"`
}

type AuditLogResponse struct {
	ID         uint                   `json:"id"`
	UserID     *uint                  `json:"user_id"`
	Username   string                 `json:"username,omitempty"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID *uint                  `json:"resource_id"`
	Method     string                 `json:"method"`
	Path       string                 `json:"path"`
	IPAddress  string                 `json:"ip_address"`
	Success    bool                   `json:"success"`
	StatusCode int                    `json:"status_code"`
	ErrorMsg   string                 `json:"error_msg,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Duration   int64                  `json:"duration"`
	RiskLevel  string                 `json:"risk_level"`
	CreatedAt  time.Time              `json:"created_at"`
}

type AuditLogListRequest struct {
	Page      int        `form:"page,default=1" validate:"min=1"`
	PageSize  int        `form:"page_size,default=20" validate:"min=1,max=100"`
	UserID    *uint      `form:"user_id"`
	Action    string     `form:"action"`
	Resource  string     `form:"resource"`
	Success   *bool      `form:"success"`
	RiskLevel string     `form:"risk_level"`
	IPAddress string     `form:"ip_address"`
	StartDate *time.Time `form:"start_date"`
	EndDate   *time.Time `form:"end_date"`
	SortBy    string     `form:"sort_by,default=created_at"`
	SortOrder string     `form:"sort_order,default=desc" validate:"oneof=asc desc"`
}

type AuditLogListResponse struct {
	Logs       []AuditLogResponse `json:"logs"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}

type SecurityEvent struct {
	ID        uint                   `json:"id" gorm:"primarykey"`
	Type      string                 `json:"type" gorm:"not null;index"`     // failed_login, suspicious_activity, etc.
	Severity  string                 `json:"severity" gorm:"not null;index"` // low, medium, high, critical
	Message   string                 `json:"message" gorm:"not null"`
	IPAddress string                 `json:"ip_address" gorm:"index"`
	UserID    *uint                  `json:"user_id,omitempty" gorm:"index"`
	UserAgent string                 `json:"user_agent"`
	Details   map[string]interface{} `json:"details,omitempty" gorm:"serializer:json"`
	Resolved  bool                   `json:"resolved" gorm:"default:false;index"`
	CreatedAt time.Time              `json:"created_at" gorm:"index"`

	// Associations
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

func (a *AuditLog) ToResponse() *AuditLogResponse {
	response := &AuditLogResponse{
		ID:         a.ID,
		UserID:     a.UserID,
		Action:     a.Action,
		Resource:   a.Resource,
		ResourceID: a.ResourceID,
		Method:     a.Method,
		Path:       a.Path,
		IPAddress:  a.IPAddress,
		Success:    a.Success,
		StatusCode: a.StatusCode,
		ErrorMsg:   a.ErrorMsg,
		Details:    a.Details,
		Duration:   a.Duration,
		RiskLevel:  a.RiskLevel,
		CreatedAt:  a.CreatedAt,
	}

	if a.User != nil {
		response.Username = a.User.Username
	}

	return response
}

// Common audit action constants
const (
	ActionLogin            = "login"
	ActionLogout           = "logout"
	ActionRegister         = "register"
	ActionPasswordChange   = "password_change"
	ActionMFAEnable        = "mfa_enable"
	ActionMFADisable       = "mfa_disable"
	ActionFileUpload       = "file_upload"
	ActionFileDownload     = "file_download"
	ActionFileDelete       = "file_delete"
	ActionFileShare        = "file_share"
	ActionFileUnshare      = "file_unshare"
	ActionPermissionGrant  = "permission_grant"
	ActionPermissionRevoke = "permission_revoke"
	ActionAccountLock      = "account_lock"
	ActionAccountUnlock    = "account_unlock"
)

// Resource type constants
const (
	ResourceUser   = "user"
	ResourceFile   = "file"
	ResourceSystem = "system"
)

// Risk level constants
const (
	RiskLevelLow      = "low"
	RiskLevelMedium   = "medium"
	RiskLevelHigh     = "high"
	RiskLevelCritical = "critical"
)
