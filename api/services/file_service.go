package services

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"zephyr-zero-file-storage/config"
	"zephyr-zero-file-storage/database"
	"zephyr-zero-file-storage/models"
	"zephyr-zero-file-storage/utils"
)

type FileService struct {
	auditService *AuditService
}

func NewFileService() *FileService {
	return &FileService{
		auditService: NewAuditService(),
	}
}

// UploadFile upload file
func (s *FileService) UploadFile(userID uint, file *multipart.FileHeader, req *models.FileUploadRequest, clientIP string) (*models.File, error) {
	// Check file size
	if file.Size > config.AppConfig.MaxFileSize {
		return nil, fmt.Errorf("file size exceeds maximum allowed size of %d bytes", config.AppConfig.MaxFileSize)
	}

	// Check file type
	if !s.isAllowedFileType(file.Header.Get("Content-Type")) {
		return nil, errors.New("file type not allowed")
	}

	// Create upload directory
	uploadDir := filepath.Join(config.AppConfig.StoragePath, fmt.Sprintf("user_%d", userID))
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return nil, err
	}

	// Generate unique filename
	fileExt := filepath.Ext(file.Filename)
	fileName := uuid.New().String() + fileExt
	filePath := filepath.Join(uploadDir, fileName)

	// Open uploaded file
	src, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer src.Close()

	// Read file content
	fileContent, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}

	// Calculate file hash
	md5Hash := utils.CalculateMD5(fileContent)
	sha256Hash := utils.CalculateSHA256(fileContent)

	// Encrypt file content
	encryptionKey := []byte(config.AppConfig.EncryptionKey)
	if len(encryptionKey) != 32 {
		return nil, errors.New("invalid encryption key length")
	}

	encryptedContent, err := utils.EncryptData(fileContent, encryptionKey)
	if err != nil {
		return nil, err
	}

	// Save encrypted file
	if err := os.WriteFile(filePath, encryptedContent, 0644); err != nil {
		return nil, err
	}

	// Create file record
	fileRecord := &models.File{
		UserID:         userID,
		FileName:       fileName,
		OriginalName:   file.Filename,
		FileSize:       file.Size,
		MimeType:       file.Header.Get("Content-Type"),
		FilePath:       filePath,
		IsEncrypted:    true,
		ChecksumMD5:    md5Hash,
		ChecksumSHA256: sha256Hash,
		IsPublic:       req.IsPublic,
		AccessLevel:    "private",
		Description:    req.Description,
		Version:        1,
	}

	if req.IsPublic {
		fileRecord.AccessLevel = "public"
		shareToken, err := utils.GenerateSecureRandomString(16)
		if err == nil {
			fileRecord.ShareToken = shareToken
		}
	}

	if err := database.DB.Create(fileRecord).Error; err != nil {
		// If database operation fails, delete the saved file
		os.Remove(filePath)
		return nil, err
	}

	// Process tags
	if len(req.Tags) > 0 {
		if err := s.processTags(fileRecord.ID, req.Tags); err != nil {
			// Log error but don't affect file upload
			fmt.Printf("Failed to process tags: %v\n", err)
		}
	}

	// Record audit log
	go s.auditService.LogAction(&userID, models.ActionFileUpload, models.ResourceFile, &fileRecord.ID, clientIP, true, map[string]interface{}{
		"file_name":    fileRecord.OriginalName,
		"file_size":    fileRecord.FileSize,
		"mime_type":    fileRecord.MimeType,
		"is_encrypted": fileRecord.IsEncrypted,
	})

	return fileRecord, nil
}

// DownloadFile download file
func (s *FileService) DownloadFile(fileID, userID uint, clientIP string) ([]byte, *models.File, error) {
	// Get file record
	var file models.File
	if err := database.DB.Preload("User").First(&file, fileID).Error; err != nil {
		return nil, nil, errors.New("file not found")
	}

	// Check permissions
	if !s.canAccessFile(&file, userID, "read") {
		go s.auditService.LogAction(&userID, models.ActionFileDownload, models.ResourceFile, &fileID, clientIP, false, map[string]interface{}{
			"file_name": file.OriginalName,
			"reason":    "access denied",
		})
		return nil, nil, errors.New("access denied")
	}

	// Read encrypted file
	encryptedContent, err := os.ReadFile(file.FilePath)
	if err != nil {
		return nil, nil, err
	}

	// Decrypt file content
	var fileContent []byte
	if file.IsEncrypted {
		encryptionKey := []byte(config.AppConfig.EncryptionKey)
		fileContent, err = utils.DecryptData(encryptedContent, encryptionKey)
		if err != nil {
			return nil, nil, err
		}
	} else {
		fileContent = encryptedContent
	}

	// Record audit log
	go s.auditService.LogAction(&userID, models.ActionFileDownload, models.ResourceFile, &fileID, clientIP, true, map[string]interface{}{
		"file_name": file.OriginalName,
		"file_size": len(fileContent),
	})

	return fileContent, &file, nil
}

// GetUserFiles get user file list
func (s *FileService) GetUserFiles(userID uint, page, pageSize int) (*models.FileListResponse, error) {
	query := database.DB.Model(&models.File{}).Where("user_id = ?", userID).Preload("Tags")

	// Calculate total count
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	// Paginated query
	offset := (page - 1) * pageSize
	var files []models.File
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&files).Error; err != nil {
		return nil, err
	}

	// Convert response
	fileResponses := make([]models.FileResponse, len(files))
	for i, file := range files {
		fileResponses[i] = *file.ToResponse()
	}

	return &models.FileListResponse{
		Files:      fileResponses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: int((total + int64(pageSize) - 1) / int64(pageSize)),
	}, nil
}

// DeleteFile delete file
func (s *FileService) DeleteFile(fileID, userID uint, clientIP string) error {
	// Get file record
	var file models.File
	if err := database.DB.First(&file, fileID).Error; err != nil {
		return errors.New("file not found")
	}

	// Check permissions (only file owner or admin can delete)
	// TODO: Check admin permissions
	if file.UserID != userID {
		go s.auditService.LogAction(&userID, models.ActionFileDelete, models.ResourceFile, &fileID, clientIP, false, map[string]interface{}{
			"reason": "access denied",
		})
		return errors.New("access denied")
	}

	// Delete physical file
	if err := os.Remove(file.FilePath); err != nil {
		fmt.Printf("Failed to delete physical file: %v\n", err)
	}

	// Delete database record
	if err := database.DB.Delete(&file).Error; err != nil {
		return err
	}

	// Record audit log
	go s.auditService.LogAction(&userID, models.ActionFileDelete, models.ResourceFile, &fileID, clientIP, true, map[string]interface{}{
		"file_name": file.OriginalName,
	})

	return nil
}

// UpdateFile update file information
func (s *FileService) UpdateFile(fileID, userID uint, req *models.FileUpdateRequest, clientIP string) (*models.File, error) {
	// Get file record
	var file models.File
	if err := database.DB.Preload("Tags").First(&file, fileID).Error; err != nil {
		return nil, errors.New("file not found")
	}

	// Check permissions
	if !s.canAccessFile(&file, userID, "write") {
		return nil, errors.New("access denied")
	}

	// Update fields
	updates := make(map[string]interface{})
	if req.FileName != "" {
		updates["file_name"] = req.FileName
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	updates["is_public"] = req.IsPublic

	// Handle access level and share token
	if req.IsPublic {
		updates["access_level"] = "public"
		if file.ShareToken == "" {
			shareToken, err := utils.GenerateSecureRandomString(16)
			if err == nil {
				updates["share_token"] = shareToken
			}
		}
	} else {
		updates["access_level"] = "private"
		updates["share_token"] = ""
	}

	if req.Metadata != nil {
		updates["metadata"] = req.Metadata
	}

	if err := database.DB.Model(&file).Updates(updates).Error; err != nil {
		return nil, err
	}

	// Handle tags
	if req.Tags != nil {
		// Clear existing tag associations
		database.DB.Model(&file).Association("Tags").Clear()
		// Add new tags
		if len(req.Tags) > 0 {
			if err := s.processTags(file.ID, req.Tags); err != nil {
				fmt.Printf("Failed to process tags: %v\n", err)
			}
		}
	}

	// Reload file with updated information
	if err := database.DB.Preload("Tags").First(&file, fileID).Error; err != nil {
		return nil, err
	}

	return &file, nil
}

// ShareFile share file
func (s *FileService) ShareFile(fileID, userID uint, req *models.FileShareRequest, clientIP string) error {
	// Get file record
	var file models.File
	if err := database.DB.First(&file, fileID).Error; err != nil {
		return errors.New("file not found")
	}

	// Check permissions
	if !s.canAccessFile(&file, userID, "share") {
		return errors.New("access denied")
	}

	// Handle public link
	if req.GeneratePublicLink {
		shareToken, err := utils.GenerateSecureRandomString(16)
		if err != nil {
			return err
		}

		updates := map[string]interface{}{
			"is_public":    true,
			"access_level": "public",
			"share_token":  shareToken,
		}

		if err := database.DB.Model(&file).Updates(updates).Error; err != nil {
			return err
		}
	}

	// Handle specific user permissions
	for _, targetUserID := range req.UserIDs {
		permission := &models.FilePermission{
			FileID:     fileID,
			UserID:     &targetUserID,
			Permission: req.Permission,
			GrantedBy:  userID,
			ExpiresAt:  req.ExpiresAt,
		}

		if err := database.DB.Create(permission).Error; err != nil {
			return err
		}
	}

	// Record audit log
	go s.auditService.LogAction(&userID, models.ActionFileShare, models.ResourceFile, &fileID, clientIP, true, map[string]interface{}{
		"file_name":            file.OriginalName,
		"permission":           req.Permission,
		"generate_public_link": req.GeneratePublicLink,
		"target_users":         len(req.UserIDs),
	})

	return nil
}

// Helper methods

// isAllowedFileType check if file type is allowed
func (s *FileService) isAllowedFileType(mimeType string) bool {
	allowedTypes := []string{
		"image/jpeg", "image/png", "image/gif",
		"application/pdf", "text/plain",
		"application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	}

	for _, allowed := range allowedTypes {
		if mimeType == allowed {
			return true
		}
	}
	return false
}

// canAccessFile check if user can access file
func (s *FileService) canAccessFile(file *models.File, userID uint, permission string) bool {
	// File owner has all permissions
	if file.UserID == userID {
		return true
	}

	// Check public access
	if file.IsPublic && permission == "read" {
		return true
	}

	// Check specific permissions
	var filePermission models.FilePermission
	err := database.DB.Where("file_id = ? AND user_id = ? AND permission = ?", file.ID, userID, permission).First(&filePermission).Error
	if err == nil {
		// Check if permission has expired
		if filePermission.ExpiresAt == nil || time.Now().Before(*filePermission.ExpiresAt) {
			return true
		}
	}

	return false
}

// processTags process file tags
func (s *FileService) processTags(fileID uint, tagNames []string) error {
	var tags []models.Tag
	// Find or create tags
	for _, tagName := range tagNames {
		var tag models.Tag
		// Create new tag if not exists
		if err := database.DB.Where("name = ?", tagName).FirstOrCreate(&tag, models.Tag{
			Name:  tagName,
			Color: "#007bff",
		}).Error; err != nil {
			return err
		}
		tags = append(tags, tag)
	}

	// Create file-tag associations
	var file models.File
	if err := database.DB.First(&file, fileID).Error; err != nil {
		return err
	}

	return database.DB.Model(&file).Association("Tags").Replace(tags)
}
