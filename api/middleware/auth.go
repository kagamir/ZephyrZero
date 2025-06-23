package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zephyr-zero-file-storage/config"
	"zephyr-zero-file-storage/database"
	"zephyr-zero-file-storage/models"
	"zephyr-zero-file-storage/services"
	"zephyr-zero-file-storage/utils"
)

// AuthMiddleware JWT authentication middleware
func AuthMiddleware() gin.HandlerFunc {
	jwtManager := utils.NewJWTManager(
		config.AppConfig.JWTSecret,
		config.AppConfig.JWTExpiration,
		config.AppConfig.RefreshExpiration,
	)

	return func(c *gin.Context) {
		// Get authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Check Bearer prefix
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization format",
			})
			c.Abort()
			return
		}

		// Extract token
		token := authHeader[len(bearerPrefix):]

		// Validate token
		claims, err := jwtManager.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		// Check if user exists and is active
		var user models.User
		if err := database.DB.First(&user, claims.UserID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not found",
			})
			c.Abort()
			return
		}

		if !user.IsActive {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Account is inactive",
			})
			c.Abort()
			return
		}

		// Check if account is locked
		if user.IsAccountLocked() {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Account is locked",
			})
			c.Abort()
			return
		}

		// Store user information in context
		c.Set("user", &user)
		c.Set("user_id", user.ID)
		c.Set("username", user.Username)
		c.Set("role", user.Role)

		c.Next()
	}
}

// RequireRole role permission middleware
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User role not found",
			})
			c.Abort()
			return
		}

		roleStr := userRole.(string)
		for _, role := range roles {
			if roleStr == role {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error": "Insufficient permissions",
		})
		c.Abort()
	}
}

// RequireAdmin admin permission middleware
func RequireAdmin() gin.HandlerFunc {
	return RequireRole("admin")
}

// RateLimitMiddleware rate limiting middleware
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use Redis to implement rate limiting logic
		// Simplified handling here, should use Redis in actual application

		c.Next()
	}
}

// AuditMiddleware audit middleware
func AuditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Record request information
		auditService := services.NewAuditService()

		c.Next()

		// Calculate duration
		duration := time.Since(startTime).Milliseconds()

		// Get user ID
		var userID *uint
		if id, exists := c.Get("user_id"); exists {
			if uid, ok := id.(uint); ok {
				userID = &uid
			}
		}

		// Record audit log
		go auditService.LogRequest(&models.AuditLog{
			UserID:     userID,
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			UserAgent:  c.Request.UserAgent(),
			IPAddress:  c.ClientIP(),
			Success:    c.Writer.Status() < 400,
			StatusCode: c.Writer.Status(),
			Duration:   duration,
		})
	}
}

// SecurityHeadersMiddleware security headers middleware
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		c.Next()
	}
}
