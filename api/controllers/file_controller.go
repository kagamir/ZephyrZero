package controllers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"zephyr-zero-file-storage/models"
	"zephyr-zero-file-storage/services"
)

type FileController struct {
	fileService *services.FileService
}

func NewFileController() *FileController {
	return &FileController{
		fileService: services.NewFileService(),
	}
}

// UploadFile upload file
func (c *FileController) UploadFile(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	// Get uploaded file
	file, err := ctx.FormFile("file")
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "No file uploaded",
		})
		return
	}

	// Parse request parameters
	var req models.FileUploadRequest
	req.Description = ctx.PostForm("description")
	req.IsPublic = ctx.PostForm("is_public") == "true"

	// Handle tags
	if tags := ctx.PostFormArray("tags"); len(tags) > 0 {
		req.Tags = tags
	}

	// Upload file
	fileRecord, err := c.fileService.UploadFile(userID.(uint), file, &req, ctx.ClientIP())
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{
		"message": "File uploaded successfully",
		"file":    fileRecord.ToResponse(),
	})
}

// GetUserFiles get user file list
func (c *FileController) GetUserFiles(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// Get file list
	response, err := c.fileService.GetUserFiles(userID.(uint), page, pageSize)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve files",
		})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// GetFile get file information
func (c *FileController) GetFile(ctx *gin.Context) {
	_, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	_, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid file ID",
		})
		return
	}

	// TODO: Implement logic to get file information
	ctx.JSON(http.StatusNotImplemented, gin.H{
		"error": "Not implemented yet",
	})
}

// DownloadFile download file
func (c *FileController) DownloadFile(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	fileID, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid file ID",
		})
		return
	}

	// Download file
	fileContent, fileRecord, err := c.fileService.DownloadFile(uint(fileID), userID.(uint), ctx.ClientIP())
	if err != nil {
		ctx.JSON(http.StatusForbidden, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Set response headers
	ctx.Header("Content-Description", "File Transfer")
	ctx.Header("Content-Type", fileRecord.MimeType)
	ctx.Header("Content-Disposition", "attachment; filename="+fileRecord.OriginalName)
	ctx.Header("Content-Transfer-Encoding", "binary")
	ctx.Header("Cache-Control", "must-revalidate")

	ctx.Data(http.StatusOK, fileRecord.MimeType, fileContent)
}

// UpdateFile update file information
func (c *FileController) UpdateFile(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	fileID, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid file ID",
		})
		return
	}

	var req models.FileUpdateRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Update file information
	fileRecord, err := c.fileService.UpdateFile(uint(fileID), userID.(uint), &req, ctx.ClientIP())
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "File updated successfully",
		"file":    fileRecord.ToResponse(),
	})
}

// DeleteFile delete file
func (c *FileController) DeleteFile(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	fileID, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid file ID",
		})
		return
	}

	// Delete file
	if err := c.fileService.DeleteFile(uint(fileID), userID.(uint), ctx.ClientIP()); err != nil {
		ctx.JSON(http.StatusForbidden, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "File deleted successfully",
	})
}

// ShareFile share file
func (c *FileController) ShareFile(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	fileID, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid file ID",
		})
		return
	}

	var req models.FileShareRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Share file
	if err := c.fileService.ShareFile(uint(fileID), userID.(uint), &req, ctx.ClientIP()); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "File shared successfully",
	})
}

// GetPublicFile get public file information
func (c *FileController) GetPublicFile(ctx *gin.Context) {
	// TODO: Implement public file access logic
	ctx.JSON(http.StatusNotImplemented, gin.H{
		"error": "Not implemented yet",
	})
}

// DownloadPublicFile download public file
func (c *FileController) DownloadPublicFile(ctx *gin.Context) {
	// TODO: Implement public file download logic
	ctx.JSON(http.StatusNotImplemented, gin.H{
		"error": "Not implemented yet",
	})
}
