package routes

import (
	"github.com/gin-gonic/gin"

	"zephyr-zero-file-storage/controllers"
	"zephyr-zero-file-storage/middleware"
)

func SetupRoutes() *gin.Engine {
	router := gin.New()

	// Global middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.SecurityHeadersMiddleware())
	router.Use(middleware.AuditMiddleware())

	// API version group
	v1 := router.Group("/api/v1")

	// Authentication related routes
	authController := controllers.NewAuthController()
	auth := v1.Group("/auth")
	{
		auth.POST("/register", authController.Register)
		auth.POST("/login", authController.Login)
		auth.POST("/refresh", authController.RefreshToken)

		// Routes requiring authentication
		authProtected := auth.Group("")
		authProtected.Use(middleware.AuthMiddleware())
		{
			authProtected.GET("/profile", authController.GetProfile)
			authProtected.POST("/logout", authController.Logout)
			authProtected.POST("/change-password", authController.ChangePassword)
		}
	}

	// File related routes
	fileController := controllers.NewFileController()
	files := v1.Group("/files")
	files.Use(middleware.AuthMiddleware())
	{
		files.POST("/upload", fileController.UploadFile)
		files.GET("", fileController.GetUserFiles)
		files.GET("/:id", fileController.GetFile)
		files.GET("/:id/download", fileController.DownloadFile)
		files.PUT("/:id", fileController.UpdateFile)
		files.DELETE("/:id", fileController.DeleteFile)
		files.POST("/:id/share", fileController.ShareFile)
	}

	// Public file access routes (no authentication required)
	public := v1.Group("/public")
	{
		public.GET("/files/:token", fileController.GetPublicFile)
		public.GET("/files/:token/download", fileController.DownloadPublicFile)
	}

	// Admin routes
	admin := v1.Group("/admin")
	admin.Use(middleware.AuthMiddleware())
	admin.Use(middleware.RequireAdmin())
	{
		auditController := controllers.NewAuditController()
		admin.GET("/audit-logs", auditController.GetAuditLogs)
		admin.GET("/security-events", auditController.GetSecurityEvents)

		userController := controllers.NewUserController()
		admin.GET("/users", userController.GetUsers)
		admin.PUT("/users/:id", userController.UpdateUser)
		admin.DELETE("/users/:id", userController.DeleteUser)
		admin.POST("/users/:id/lock", userController.LockUser)
		admin.POST("/users/:id/unlock", userController.UnlockUser)
	}

	// Health check
	v1.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "healthy",
			"message": "Zephyr Zero File Storage API is running",
		})
	})

	return router
}
