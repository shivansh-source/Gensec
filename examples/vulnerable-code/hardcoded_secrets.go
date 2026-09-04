// Package vulnerable holds standalone example snippets scanned by GenSec's
// demo (see README Quick Start). They are never built or executed as part
// of GenSec itself — GenSec only reads them as text — so this package name
// just needs to compile, not run as a command.
package vulnerable

import (
	"fmt"
)

// VULNERABLE: Hardcoded API Keys
const (
	// SECURITY ISSUE: Hardcoded credentials
	apiKey     = "sk-1234567890abcdefghijk"
	dbPassword = "admin@123456"
	jwtSecret  = "supersecretjwtkey12345"
)

// GetAPIKey - Exposes hardcoded API key
func GetAPIKey() string {
	return apiKey
}

// ConnectDatabase - Uses hardcoded password
func ConnectDatabase() error {
	connectionString := fmt.Sprintf("postgres://admin:%s@localhost:5432/mydb", dbPassword)
	fmt.Println("Connecting to:", connectionString) // LOGS SENSITIVE DATA!
	return nil
}

// ValidateToken - Using hardcoded JWT secret
func ValidateToken(token string) bool {
	// VULNERABILITY: Hardcoded secret used for token validation
	return token == jwtSecret
}

// InitializeConfig - Multiple hardcoded secrets
func InitializeConfig() map[string]string {
	config := map[string]string{
		"aws_access_key": "AKIAIOSFODNN7EXAMPLE",
		"aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"slack_webhook":  "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
	}
	return config
}

// FIXED: Using environment variables
func GetAPIKeySecure() string {
	// Should use: os.Getenv("API_KEY")
	return "" // Will be loaded from environment
}

func ConnectDatabaseSecure() error {
	// Should use: os.Getenv("DB_PASSWORD")
	fmt.Println("Connecting to database...")
	return nil
}
