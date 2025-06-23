package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"

	"zephyr-zero-file-storage/config"
	"zephyr-zero-file-storage/database"
	"zephyr-zero-file-storage/routes"
)

func main() {
	// Load configuration
	if err := config.LoadConfig(); err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Initialize database
	if err := database.InitDatabase(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer database.CloseDatabase()

	// Create necessary directories
	if err := createDirectories(); err != nil {
		log.Fatal("Failed to create directories:", err)
	}

	// Set Gin mode
	if config.AppConfig.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Setup routes
	router := routes.SetupRoutes()

	// Start server
	addr := fmt.Sprintf("%s:%s", config.AppConfig.ServerHost, config.AppConfig.ServerPort)
	log.Printf("Starting server on %s", addr)
	log.Printf("Environment: %s", config.AppConfig.Environment)

	if err := router.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func createDirectories() error {
	dirs := []string{
		config.AppConfig.StoragePath,
		"logs",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	return nil
}
