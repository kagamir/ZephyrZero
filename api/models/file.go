package models

import (
	"time"

	"gorm.io/gorm"
)

type File struct {
	ID           uint   `json:"id" gorm:"primarykey"`
	UserID       uint   `json:"user_id" gorm:"not null;index"`
	FileName     string `json:"file_name" gorm:"not null"`
	OriginalName string `json:"original_name" gorm:"not null"`
	FileSize     int64  `json:"file_size"`
	MimeType     string `json:"mime_type"`
	FilePath     string `json:"-" gorm:"not null"` // Actual storage path, not returned to client

	// Security related
	IsEncrypted    bool   `json:"is_encrypted" gorm:"default:true"`
	ChecksumMD5    string `json:"checksum_md5"`
	ChecksumSHA256 string `json:"checksum_sha256"`

	// Permission control
	IsPublic    bool   `json:"is_public" gorm:"default:false"`
	AccessLevel string `json:"access_level" gorm:"default:private"` // private, shared, public
	ShareToken  string `json:"share_token,omitempty" gorm:"uniqueIndex"`

	// Metadata
	Description string            `json:"description"`
	Tags        []Tag             `json:"tags,omitempty" gorm:"many2many:file_tags;"`
	Metadata    map[string]string `json:"metadata,omitempty" gorm:"serializer:json"`

	// Version control
	Version  int   `json:"version" gorm:"default:1"`
	ParentID *uint `json:"parent_id,omitempty"` // For version control

	// Audit fields
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	// Associations
	User        User             `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Permissions []FilePermission `json:"permissions,omitempty" gorm:"foreignKey:FileID"`
	Children    []File           `json:"children,omitempty" gorm:"foreignKey:ParentID"`
	AuditLogs   []AuditLog       `json:"audit_logs,omitempty" gorm:"foreignKey:ResourceID"`
}

type Tag struct {
	ID    uint   `json:"id" gorm:"primarykey"`
	Name  string `json:"name" gorm:"uniqueIndex;not null"`
	Color string `json:"color" gorm:"default:#007bff"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

type FilePermission struct {
	ID         uint       `json:"id" gorm:"primarykey"`
	FileID     uint       `json:"file_id" gorm:"not null;index"`
	UserID     *uint      `json:"user_id,omitempty" gorm:"index"`
	Permission string     `json:"permission" gorm:"not null"` // read, write, delete, share
	GrantedBy  uint       `json:"granted_by" gorm:"not null"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	// Associations
	File    File  `json:"file,omitempty" gorm:"foreignKey:FileID"`
	User    *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Granter User  `json:"granter,omitempty" gorm:"foreignKey:GrantedBy"`
}

type FileUploadRequest struct {
	Description string   `form:"description"`
	Tags        []string `form:"tags"`
	IsPublic    bool     `form:"is_public"`
}

type FileUpdateRequest struct {
	FileName    string            `json:"file_name" validate:"omitempty,min=1"`
	Description string            `json:"description"`
	Tags        []string          `json:"tags"`
	IsPublic    bool              `json:"is_public"`
	Metadata    map[string]string `json:"metadata"`
}

type FileShareRequest struct {
	Permission         string     `json:"permission" validate:"required,oneof=read write"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	UserIDs            []uint     `json:"user_ids,omitempty"`
	GeneratePublicLink bool       `json:"generate_public_link"`
}

type FileResponse struct {
	ID           uint              `json:"id"`
	FileName     string            `json:"file_name"`
	OriginalName string            `json:"original_name"`
	FileSize     int64             `json:"file_size"`
	MimeType     string            `json:"mime_type"`
	IsEncrypted  bool              `json:"is_encrypted"`
	IsPublic     bool              `json:"is_public"`
	AccessLevel  string            `json:"access_level"`
	Description  string            `json:"description"`
	Tags         []Tag             `json:"tags"`
	Metadata     map[string]string `json:"metadata"`
	Version      int               `json:"version"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	User         *UserResponse     `json:"user,omitempty"`
	ShareToken   string            `json:"share_token,omitempty"`
}

type FileListResponse struct {
	Files      []FileResponse `json:"files"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}

func (f *File) ToResponse() *FileResponse {
	response := &FileResponse{
		ID:           f.ID,
		FileName:     f.FileName,
		OriginalName: f.OriginalName,
		FileSize:     f.FileSize,
		MimeType:     f.MimeType,
		IsEncrypted:  f.IsEncrypted,
		IsPublic:     f.IsPublic,
		AccessLevel:  f.AccessLevel,
		Description:  f.Description,
		Tags:         f.Tags,
		Metadata:     f.Metadata,
		Version:      f.Version,
		CreatedAt:    f.CreatedAt,
		UpdatedAt:    f.UpdatedAt,
	}

	if f.User.ID != 0 {
		response.User = f.User.ToResponse()
	}

	if f.ShareToken != "" {
		response.ShareToken = f.ShareToken
	}

	return response
}

func (f *File) CanBeAccessedBy(userID uint, permission string) bool {
	// File owner has all permissions
	if f.UserID == userID {
		return true
	}

	// Check public access
	if f.IsPublic && permission == "read" {
		return true
	}

	// Check specific permissions (need to query FilePermission in database)
	// Simplified handling here, actual application should query permission table
	return false
}
