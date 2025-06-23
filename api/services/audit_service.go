package services

import (
	"log"
	"time"

	"zephyr-zero-file-storage/database"
	"zephyr-zero-file-storage/models"
)

type AuditService struct{}

func NewAuditService() *AuditService {
	return &AuditService{}
}

// LogAction log user action
func (s *AuditService) LogAction(userID *uint, action, resource string, resourceID *uint, ipAddress string, success bool, details map[string]interface{}) {
	auditLog := &models.AuditLog{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		IPAddress:  ipAddress,
		Success:    success,
		Details:    details,
		RiskLevel:  s.calculateRiskLevel(action, success),
		CreatedAt:  time.Now(),
	}

	if err := database.DB.Create(auditLog).Error; err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
}

// LogRequest log HTTP request
func (s *AuditService) LogRequest(auditLog *models.AuditLog) {
	auditLog.CreatedAt = time.Now()
	auditLog.RiskLevel = s.calculateRiskLevel(auditLog.Action, auditLog.Success)

	if err := database.DB.Create(auditLog).Error; err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
}

// GetAuditLogs get audit log list
func (s *AuditService) GetAuditLogs(req *models.AuditLogListRequest) (*models.AuditLogListResponse, error) {
	query := database.DB.Model(&models.AuditLog{}).Preload("User")

	// Apply filter conditions
	if req.UserID != nil {
		query = query.Where("user_id = ?", *req.UserID)
	}
	if req.Action != "" {
		query = query.Where("action = ?", req.Action)
	}
	if req.Resource != "" {
		query = query.Where("resource = ?", req.Resource)
	}
	if req.Success != nil {
		query = query.Where("success = ?", *req.Success)
	}
	if req.RiskLevel != "" {
		query = query.Where("risk_level = ?", req.RiskLevel)
	}
	if req.IPAddress != "" {
		query = query.Where("ip_address = ?", req.IPAddress)
	}
	if req.StartDate != nil {
		query = query.Where("created_at >= ?", *req.StartDate)
	}
	if req.EndDate != nil {
		query = query.Where("created_at <= ?", *req.EndDate)
	}

	// Calculate total count
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	// Apply sorting and pagination
	offset := (req.Page - 1) * req.PageSize
	query = query.Order(req.SortBy + " " + req.SortOrder).Offset(offset).Limit(req.PageSize)

	var auditLogs []models.AuditLog
	if err := query.Find(&auditLogs).Error; err != nil {
		return nil, err
	}

	// Convert response
	logs := make([]models.AuditLogResponse, len(auditLogs))
	for i, log := range auditLogs {
		logs[i] = *log.ToResponse()
	}

	return &models.AuditLogListResponse{
		Logs:       logs,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: int((total + int64(req.PageSize) - 1) / int64(req.PageSize)),
	}, nil
}

// LogSecurityEvent log security event
func (s *AuditService) LogSecurityEvent(eventType, severity, message, ipAddress string, userID *uint, details map[string]interface{}) {
	event := &models.SecurityEvent{
		Type:      eventType,
		Severity:  severity,
		Message:   message,
		IPAddress: ipAddress,
		UserID:    userID,
		Details:   details,
		Resolved:  false,
		CreatedAt: time.Now(),
	}

	if err := database.DB.Create(event).Error; err != nil {
		log.Printf("Failed to create security event: %v", err)
	}
}

// calculateRiskLevel calculate risk level
func (s *AuditService) calculateRiskLevel(action string, success bool) string {
	// Failed operations have higher risk
	if !success {
		switch action {
		case models.ActionLogin, models.ActionPasswordChange:
			return models.RiskLevelHigh
		case models.ActionFileDelete, models.ActionPermissionGrant:
			return models.RiskLevelMedium
		default:
			return models.RiskLevelLow
		}
	}

	// Successful sensitive operations
	switch action {
	case models.ActionFileDelete, models.ActionPermissionGrant, models.ActionPermissionRevoke:
		return models.RiskLevelMedium
	case models.ActionAccountLock, models.ActionAccountUnlock:
		return models.RiskLevelHigh
	default:
		return models.RiskLevelLow
	}
}
