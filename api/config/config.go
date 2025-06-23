package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// 服务配置
	ServerPort  string
	ServerHost  string
	Environment string

	// 数据库配置
	DatabaseURL    string
	DatabaseDriver string

	// Redis配置
	RedisURL      string
	RedisPassword string
	RedisDB       int

	// JWT配置
	JWTSecret         string
	JWTExpiration     time.Duration
	RefreshExpiration time.Duration

	// 文件存储配置
	StoragePath   string
	MaxFileSize   int64
	AllowedTypes  []string
	EncryptionKey string

	// 零信任安全配置
	EnableMFA        bool
	SessionTimeout   time.Duration
	MaxLoginAttempts int
	LockoutDuration  time.Duration

	// 审计日志配置
	AuditLogPath string
	LogLevel     string

	// MinIO S3配置
	S3Endpoint   string
	S3AccessKey  string
	S3SecretKey  string
	S3BucketName string
	S3UseSSL     bool
}

var AppConfig *Config

func LoadConfig() error {
	// 加载.env文件
	godotenv.Load()

	AppConfig = &Config{
		ServerPort:  getEnv("SERVER_PORT", "4345"),
		ServerHost:  getEnv("SERVER_HOST", "localhost"),
		Environment: getEnv("ENVIRONMENT", "development"),

		DatabaseURL:    getEnv("DATABASE_URL", "file:./storage.db"),
		DatabaseDriver: getEnv("DATABASE_DRIVER", "sqlite"),

		RedisURL:      getEnv("REDIS_URL", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvAsInt("REDIS_DB", 0),

		JWTSecret:         getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-in-production"),
		JWTExpiration:     getEnvAsDuration("JWT_EXPIRATION", "15m"),
		RefreshExpiration: getEnvAsDuration("REFRESH_EXPIRATION", "7d"),

		StoragePath:   getEnv("STORAGE_PATH", "./uploads"),
		MaxFileSize:   getEnvAsInt64("MAX_FILE_SIZE", 10*1024*1024), // 10MB
		AllowedTypes:  []string{"image/jpeg", "image/png", "image/gif", "application/pdf", "text/plain"},
		EncryptionKey: getEnv("ENCRYPTION_KEY", "32-byte-key-for-aes-256-encryption"),

		EnableMFA:        getEnvAsBool("ENABLE_MFA", true),
		SessionTimeout:   getEnvAsDuration("SESSION_TIMEOUT", "30m"),
		MaxLoginAttempts: getEnvAsInt("MAX_LOGIN_ATTEMPTS", 5),
		LockoutDuration:  getEnvAsDuration("LOCKOUT_DURATION", "15m"),

		AuditLogPath: getEnv("AUDIT_LOG_PATH", "./logs/audit.log"),
		LogLevel:     getEnv("LOG_LEVEL", "info"),

		S3Endpoint:   getEnv("S3_ENDPOINT", ""),
		S3AccessKey:  getEnv("S3_ACCESS_KEY", ""),
		S3SecretKey:  getEnv("S3_SECRET_KEY", ""),
		S3BucketName: getEnv("S3_BUCKET_NAME", "zephyr-zero-files"),
		S3UseSSL:     getEnvAsBool("S3_USE_SSL", true),
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsInt64(key string, defaultValue int64) int64 {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseInt(valueStr, 10, 64); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseBool(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue string) time.Duration {
	valueStr := getEnv(key, defaultValue)
	if value, err := time.ParseDuration(valueStr); err == nil {
		return value
	}
	// 如果解析失败，使用默认值再次解析
	if value, err := time.ParseDuration(defaultValue); err == nil {
		return value
	}
	return time.Hour // 最后的默认值
}
