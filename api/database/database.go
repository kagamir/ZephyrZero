package database

import (
	"log"
	"os"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"zephyr-zero-file-storage/config"
	"zephyr-zero-file-storage/models"
)

var DB *gorm.DB

func InitDatabase() error {
	var err error

	// Create log directory
	if err := os.MkdirAll("logs", 0755); err != nil {
		return err
	}

	// Configure database logger
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Silent,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	// Connect to database
	DB, err = gorm.Open(sqlite.Open(config.AppConfig.DatabaseURL), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		return err
	}

	// Configure connection pool
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Auto migrate
	if err := AutoMigrate(); err != nil {
		return err
	}

	return nil
}

func AutoMigrate() error {
	return DB.AutoMigrate(
		&models.User{},
		&models.File{},
		&models.Tag{},
		&models.FilePermission{},
		&models.AuditLog{},
		&models.SecurityEvent{},
	)
}

func CloseDatabase() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
