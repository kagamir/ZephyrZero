package services

import (
	"errors"
	"time"

	"zephyr-zero-file-storage/config"
	"zephyr-zero-file-storage/database"
	"zephyr-zero-file-storage/models"
	"zephyr-zero-file-storage/utils"
)

type AuthService struct {
	jwtManager   *utils.JWTManager
	auditService *AuditService
}

func NewAuthService() *AuthService {
	jwtManager := utils.NewJWTManager(
		config.AppConfig.JWTSecret,
		config.AppConfig.JWTExpiration,
		config.AppConfig.RefreshExpiration,
	)

	return &AuthService{
		jwtManager:   jwtManager,
		auditService: NewAuditService(),
	}
}

// Register user registration
func (s *AuthService) Register(req *models.RegisterRequest, clientIP string) (*models.User, error) {
	// Validate if username and email already exist
	var existingUser models.User
	if err := database.DB.Where("username = ? OR email = ?", req.Username, req.Email).First(&existingUser).Error; err == nil {
		return nil, errors.New("username or email already exists")
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &models.User{
		Username:   req.Username,
		Email:      req.Email,
		Password:   hashedPassword,
		Role:       "user",
		IsActive:   true,
		IsVerified: false,
		MFAEnabled: false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := database.DB.Create(user).Error; err != nil {
		return nil, err
	}

	// Record audit log
	go s.auditService.LogAction(nil, models.ActionRegister, models.ResourceUser, &user.ID, clientIP, true, map[string]interface{}{
		"username": user.Username,
		"email":    user.Email,
	})

	return user, nil
}

// Login user login
func (s *AuthService) Login(req *models.LoginRequest, clientIP string) (*models.TokenResponse, *models.User, error) {
	// Find user
	var user models.User
	if err := database.DB.Where("username = ? OR email = ?", req.Username, req.Username).First(&user).Error; err != nil {
		// Record failed login attempt
		go s.auditService.LogAction(nil, models.ActionLogin, models.ResourceUser, nil, clientIP, false, map[string]interface{}{
			"username": req.Username,
			"reason":   "user not found",
		})
		return nil, nil, errors.New("invalid credentials")
	}

	// Check account status
	if !user.IsActive {
		go s.auditService.LogAction(&user.ID, models.ActionLogin, models.ResourceUser, &user.ID, clientIP, false, map[string]interface{}{
			"reason": "account inactive",
		})
		return nil, nil, errors.New("account is inactive")
	}

	if user.IsAccountLocked() {
		go s.auditService.LogAction(&user.ID, models.ActionLogin, models.ResourceUser, &user.ID, clientIP, false, map[string]interface{}{
			"reason": "account locked",
		})
		return nil, nil, errors.New("account is locked")
	}

	// Verify password
	if !utils.CheckPasswordHash(req.Password, user.Password) {
		// Increase failed login attempts
		user.LoginAttempts++
		if user.LoginAttempts >= 5 {
			lockUntil := time.Now().Add(15 * time.Minute)
			user.LockedUntil = &lockUntil
		}
		database.DB.Save(&user)

		go s.auditService.LogAction(&user.ID, models.ActionLogin, models.ResourceUser, &user.ID, clientIP, false, map[string]interface{}{
			"reason":         "invalid password",
			"login_attempts": user.LoginAttempts,
		})
		return nil, nil, errors.New("invalid credentials")
	}

	// Check MFA
	if user.MFAEnabled {
		if req.MFACode == "" {
			return nil, nil, errors.New("MFA code required")
		}

		// Verify MFA code (should implement TOTP verification here)
		// Simplified handling, actual application should integrate TOTP library
		if req.MFACode != "123456" { // Mock verification
			go s.auditService.LogAction(&user.ID, models.ActionLogin, models.ResourceUser, &user.ID, clientIP, false, map[string]interface{}{
				"reason": "invalid MFA code",
			})
			return nil, nil, errors.New("invalid MFA code")
		}
	}

	// Generate token pair
	accessToken, refreshToken, err := s.jwtManager.GenerateTokenPair(user.ID, user.Username, user.Role)
	if err != nil {
		return nil, nil, err
	}

	// Update user login information
	user.LoginAttempts = 0
	user.LockedUntil = nil
	user.LastLoginAt = &time.Time{}
	*user.LastLoginAt = time.Now()
	user.LastLoginIP = clientIP
	user.RefreshToken = refreshToken
	expiry := time.Now().Add(config.AppConfig.RefreshExpiration)
	user.TokenExpiry = &expiry

	database.DB.Save(&user)

	// Record successful login
	go s.auditService.LogAction(&user.ID, models.ActionLogin, models.ResourceUser, &user.ID, clientIP, true, map[string]interface{}{
		"username": user.Username,
		"role":     user.Role,
	})

	return &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(config.AppConfig.JWTExpiration.Seconds()),
		TokenType:    "Bearer",
	}, &user, nil
}

// Logout user logout
func (s *AuthService) Logout(userID uint, clientIP string) error {
	// Clear user's refresh token
	if err := database.DB.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"refresh_token": nil,
		"token_expiry":  nil,
	}).Error; err != nil {
		return err
	}

	// Record logout log
	go s.auditService.LogAction(&userID, models.ActionLogout, models.ResourceUser, &userID, clientIP, true, nil)

	return nil
}

// RefreshToken refresh access token
func (s *AuthService) RefreshToken(refreshToken, clientIP string) (*models.TokenResponse, error) {
	// Validate refresh token
	claims, err := s.jwtManager.ValidateToken(refreshToken)
	if err != nil {
		go s.auditService.LogAction(nil, "refresh_token", models.ResourceUser, nil, clientIP, false, map[string]interface{}{
			"reason": "invalid token",
		})
		return nil, errors.New("invalid refresh token")
	}

	// Check refresh token in database
	var user models.User
	if err := database.DB.Where("id = ? AND refresh_token = ?", claims.UserID, refreshToken).First(&user).Error; err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Check if token has expired
	if user.TokenExpiry != nil && time.Now().After(*user.TokenExpiry) {
		return nil, errors.New("refresh token expired")
	}

	// Generate new access token
	newAccessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, user.Role)
	if err != nil {
		return nil, err
	}

	go s.auditService.LogAction(&user.ID, "refresh_token", models.ResourceUser, &user.ID, clientIP, true, nil)

	return &models.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(config.AppConfig.JWTExpiration.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// ChangePassword change password
func (s *AuthService) ChangePassword(userID uint, req *models.ChangePasswordRequest, clientIP string) error {
	// Get user
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		return errors.New("user not found")
	}

	// Verify current password
	if !utils.CheckPasswordHash(req.CurrentPassword, user.Password) {
		go s.auditService.LogAction(&userID, models.ActionPasswordChange, models.ResourceUser, &userID, clientIP, false, map[string]interface{}{
			"reason": "invalid current password",
		})
		return errors.New("current password is incorrect")
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return err
	}

	// Update password
	if err := database.DB.Model(&user).Update("password", hashedPassword).Error; err != nil {
		return err
	}

	// Record password change log
	go s.auditService.LogAction(&userID, models.ActionPasswordChange, models.ResourceUser, &userID, clientIP, true, nil)

	return nil
}

// GetUserProfile get user profile
func (s *AuthService) GetUserProfile(userID uint) (*models.User, error) {
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		return nil, errors.New("user not found")
	}

	return &user, nil
}

// ValidateToken validate token
func (s *AuthService) ValidateToken(token string) (*utils.JWTClaims, error) {
	return s.jwtManager.ValidateToken(token)
}
