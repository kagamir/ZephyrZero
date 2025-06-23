# ZephyrZero Zero Trust File Storage Backend

This is an online file storage backend system based on Go language and zero trust architecture.

## Features

### 🔐 Zero Trust Security Architecture
- **Never Trust, Always Verify**: Every request requires authentication and authorization
- **Principle of Least Privilege**: Users can only access resources they are authorized for
- **Strong Authentication**: Supports JWT tokens and Multi-Factor Authentication (MFA)
- **Session Management**: Intelligent session timeout and account lockout mechanisms

### 🔒 Data Security
- **End-to-End Encryption**: Files are encrypted with AES-256 during storage
- **Transmission Security**: HTTPS enforced encrypted transmission
- **Data Integrity**: MD5 and SHA256 hash verification
- **Security Headers**: Complete HTTP security headers configuration

### 📊 Audit and Monitoring
- **Comprehensive Audit Logs**: Records all user operations and system events
- **Security Event Monitoring**: Real-time detection and recording of suspicious activities
- **Risk Assessment**: Automatic assessment of operation risk levels
- **Compliance Support**: Meets data governance and compliance requirements

### 🚀 Modern Architecture
- **RESTful API**: Standard REST API design
- **Microservice Friendly**: Modular design, easy to extend
- **High Performance**: Gin framework provides high-performance HTTP services
- **Database Agnostic**: Supports SQLite, MySQL, PostgreSQL, etc.

## Quick Start

### Requirements
- Go 1.21+
- SQLite3 (or other supported databases)

### Installation Steps

1. **Clone Project**
```bash
git clone <repository-url>
cd ZephyrZero/api
```

2. **Install Dependencies**
```bash
go mod tidy
```

3. **Configure Environment Variables**
```bash
cp .env.example .env
# Edit .env file to set your configuration
```

4. **Start Service**
```bash
go run main.go
```

The service will start at `http://localhost:8080`.

## API Documentation

### Authentication

#### User Registration
```
POST /api/v1/auth/register
Content-Type: application/json

{
  "username": "your_username",
  "email": "your_email@example.com",
  "password": "your_password",
  "confirm_password": "your_password"
}
```

#### User Login
```
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "your_username",
  "password": "your_password",
  "mfa_code": "123456"  // Optional, required when MFA is enabled
}
```

#### Get User Profile
```
GET /api/v1/auth/profile
Authorization: Bearer <access_token>
```

### File Management

#### Upload File
```
POST /api/v1/files/upload
Authorization: Bearer <access_token>
Content-Type: multipart/form-data

file: <binary_file>
description: "File description"
is_public: false
tags: ["tag1", "tag2"]
```

#### Get File List
```
GET /api/v1/files?page=1&page_size=20
Authorization: Bearer <access_token>
```

#### Download File
```
GET /api/v1/files/{file_id}/download
Authorization: Bearer <access_token>
```

#### Delete File
```
DELETE /api/v1/files/{file_id}
Authorization: Bearer <access_token>
```

### Admin Functions

#### Get Audit Logs
```
GET /api/v1/admin/audit-logs?page=1&page_size=20
Authorization: Bearer <admin_access_token>
```

## Security Configuration

### JWT Secret
In production environment, please change `JWT_SECRET` to a strong random key:
```bash
JWT_SECRET=$(openssl rand -base64 32)
```

### Encryption Key
File encryption requires a 32-byte AES key:
```bash
ENCRYPTION_KEY=$(openssl rand -base64 32)
```

### HTTPS Configuration
In production environment, it's recommended to use a reverse proxy (like Nginx) to handle HTTPS:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Deployment

### Docker Deployment
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/main .
COPY --from=builder /app/.env.example .env

CMD ["./main"]
```

### Environment Variables Configuration
Important environment variables:

- `JWT_SECRET`: JWT signing key (must be changed in production)
- `ENCRYPTION_KEY`: File encryption key (32 bytes)
- `DATABASE_URL`: Database connection string
- `SERVER_PORT`: Server port (default: 8080)
- `STORAGE_PATH`: File storage path
- `AUDIT_LOG_PATH`: Audit log file path

## Project Structure

```
api/
├── main.go                 # Application entry point
├── config/                 # Configuration management
├── controllers/            # Request handlers
├── middleware/             # Middleware components
├── models/                 # Data models
├── services/               # Business logic
├── utils/                  # Utility functions
├── database/               # Database connection and migration
├── routes/                 # Route definitions
├── uploads/                # File storage directory
└── logs/                   # Log files
```
