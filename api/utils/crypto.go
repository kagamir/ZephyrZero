package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword uses bcrypt to hash password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash verifies password hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateRandomKey generates random key
func GenerateRandomKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	return key, err
}

// EncryptFile encrypts file
func EncryptFile(inputPath, outputPath string, key []byte) error {
	// Read original file
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Create CFB mode encrypter
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt data
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Write IV and ciphertext to file
	encryptedData := append(iv, ciphertext...)
	return os.WriteFile(outputPath, encryptedData, 0644)
}

// DecryptFile decrypts file
func DecryptFile(inputPath, outputPath string, key []byte) error {
	// Read encrypted file
	encryptedData, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	// Extract IV
	if len(encryptedData) < aes.BlockSize {
		return fmt.Errorf("encrypted file too short")
	}

	iv := encryptedData[:aes.BlockSize]
	ciphertext := encryptedData[aes.BlockSize:]

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Create CFB mode decrypter
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt data
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	// Write decrypted file
	return os.WriteFile(outputPath, plaintext, 0644)
}

// EncryptData encrypts data
func EncryptData(data []byte, key []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Create CFB mode encrypter
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt data
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	// Return IV+ciphertext
	return append(iv, ciphertext...), nil
}

// DecryptData decrypts data
func DecryptData(encryptedData []byte, key []byte) ([]byte, error) {
	// Extract IV
	if len(encryptedData) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	iv := encryptedData[:aes.BlockSize]
	ciphertext := encryptedData[aes.BlockSize:]

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create CFB mode decrypter
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt data
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// CalculateMD5 calculates MD5 hash
func CalculateMD5(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// CalculateSHA256 calculates SHA256 hash
func CalculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// CalculateFileMD5 calculates file MD5 hash
func CalculateFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// CalculateFileSHA256 calculates file SHA256 hash
func CalculateFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// GenerateSecureRandomString generates secure random string
func GenerateSecureRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}

	return string(bytes), nil
}
