# Build stage
FROM golang:1.21-alpine AS builder

# Install necessary packages
RUN apk update && apk add --no-cache git

WORKDIR /app

# Copy go module files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build application
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o main .

# Runtime stage
FROM alpine:latest

# Install ca-certificates and sqlite
RUN apk --no-cache add ca-certificates sqlite

WORKDIR /root/

# Copy executable from build stage
COPY --from=builder /app/main .

# Copy configuration files
COPY --from=builder /app/.env.example .env

# Create necessary directories
RUN mkdir -p uploads logs

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

# Run application
CMD ["./main"] 