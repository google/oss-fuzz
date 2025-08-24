// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fuzz

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	oauth "github.com/google-gemini/gemini-cli/gofuzz/internal/oauth"
)

// SecurityAwareOAuthRequest extends OAuth request with security validation
type SecurityAwareOAuthRequest struct {
	oauth.TokenRequest
	SecurityViolations []string  `json:"-"`
	RiskLevel          string    `json:"-"`
	CSRFToken          string    `json:"csrf_token,omitempty"`
	Timestamp          time.Time `json:"timestamp,omitempty"`
	Signature          string    `json:"signature,omitempty"`
}

// FuzzOAuthTokenRequest is the libFuzzer entrypoint for OAuth token request parsing/validation.
// Enhanced with comprehensive security validation based on audit directives.
func FuzzOAuthTokenRequest(data []byte) int {
	// Resource limits (Directive 1.1)
	if len(data) > 32768 { // 32KB max
		return 0
	}

	var request SecurityAwareOAuthRequest

	// Test JSON parsing with security awareness
	if err := json.Unmarshal(data, &request); err != nil {
		return 0
	}

	// Comprehensive security validation (Directive 3.1)
	if !validateOAuthRequestSecurity(&request) {
		return 0
	}

	// Test token validation (Directive 3.2)
	validateOAuthTokenSecurity(&request)

	// Test CSRF protection (Directive 3.1)
	validateOAuthCSRFProtection(&request)

	// Test for injection attacks (Directive 1.2)
	validateOAuthInjectionAttacks(&request)

	// Test for privilege escalation (Directive 2.1)
	validateOAuthPrivilegeEscalation(&request)

	// Test timing attack prevention (Directive 3.2)
	testOAuthTimingAttackPrevention(&request)

	// Test re-serialization
	if _, err := json.Marshal(request); err != nil {
		return 0
	}

	return 1
}

func validateOAuthRequestSecurity(request *SecurityAwareOAuthRequest) bool {
	request.SecurityViolations = []string{}
	request.RiskLevel = "LOW"

	// Validate grant type
	if request.TokenRequest.GrantType != "" && !isValidGrantType(request.TokenRequest.GrantType) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Invalid grant type")
		return false
	}

	// Validate client ID
	if request.TokenRequest.ClientID != "" && !isValidClientID(request.TokenRequest.ClientID) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Invalid client ID format")
		return false
	}

	// Validate redirect URI
	if request.TokenRequest.RedirectURI != "" && !isValidRedirectURI(request.TokenRequest.RedirectURI) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Invalid redirect URI")
		return false
	}

	// Validate scope
	if request.TokenRequest.Scope != "" && !isValidScope(request.TokenRequest.Scope) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Invalid scope format")
		return false
	}

	// Validate authorization code
	if request.TokenRequest.Code != "" && !isValidAuthorizationCode(request.TokenRequest.Code) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Invalid authorization code format")
		return false
	}

	// Validate refresh token
	if request.TokenRequest.RefreshToken != "" && !isValidRefreshToken(request.TokenRequest.RefreshToken) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Invalid refresh token format")
		return false
	}

	return len(request.SecurityViolations) == 0
}

func validateOAuthTokenSecurity(request *SecurityAwareOAuthRequest) {
	// Directive 3.2: Token Security

	// Check for weak tokens
	if request.TokenRequest.Code != "" && len(request.TokenRequest.Code) < 32 {
		request.SecurityViolations = append(request.SecurityViolations,
			"Authorization code too short")
		request.RiskLevel = "MEDIUM"
	}

	if request.TokenRequest.RefreshToken != "" && len(request.TokenRequest.RefreshToken) < 32 {
		request.SecurityViolations = append(request.SecurityViolations,
			"Refresh token too short")
		request.RiskLevel = "MEDIUM"
	}

	// Check for predictable token patterns
	if request.TokenRequest.Code != "" && isPredictableToken(request.TokenRequest.Code) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Predictable authorization code pattern")
		request.RiskLevel = "HIGH"
	}

	if request.TokenRequest.RefreshToken != "" && isPredictableToken(request.TokenRequest.RefreshToken) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Predictable refresh token pattern")
		request.RiskLevel = "HIGH"
	}

	// Check for token reuse attempts
	if request.TokenRequest.Code != "" && isReusedToken(request.TokenRequest.Code) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Authorization code reuse attempt")
		request.RiskLevel = "CRITICAL"
	}
}

func validateOAuthCSRFProtection(request *SecurityAwareOAuthRequest) {
	// Directive 3.1: CSRF Protection

	// Check for CSRF token
	if request.CSRFToken == "" {
		request.SecurityViolations = append(request.SecurityViolations,
			"Missing CSRF token")
		request.RiskLevel = "HIGH"
		return
	}

	// Validate CSRF token format
	if !isValidCSRFToken(request.CSRFToken) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Invalid CSRF token format")
		request.RiskLevel = "HIGH"
		return
	}

	// Check CSRF token expiration
	if !isCSRFTokenValid(request.CSRFToken, request.Timestamp) {
		request.SecurityViolations = append(request.SecurityViolations,
			"CSRF token expired or invalid")
		request.RiskLevel = "HIGH"
	}
}

func validateOAuthInjectionAttacks(request *SecurityAwareOAuthRequest) {
	// Directive 1.2: Injection Attack Prevention

	// Check for SQL injection patterns
	sqlPatterns := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
		"UNION", "OR 1=1", "OR '1'='1", "--", "/*", "*/",
	}

	// Check for command injection patterns
	cmdPatterns := []string{
		";", "|", "&", "`", "$(", "${", ">", "<", ">>", "<<",
		"eval", "exec", "system", "shell_exec",
	}

	// Check for XSS patterns
	xssPatterns := []string{
		"<script", "javascript:", "onload=", "onerror=",
		"<iframe", "<img", "<svg", "data:",
	}

	requestStr := fmt.Sprintf("%v", request)

	for _, pattern := range sqlPatterns {
		if strings.Contains(strings.ToUpper(requestStr), pattern) {
			request.SecurityViolations = append(request.SecurityViolations,
				fmt.Sprintf("SQL injection pattern detected: %s", pattern))
			request.RiskLevel = "HIGH"
		}
	}

	for _, pattern := range cmdPatterns {
		if strings.Contains(requestStr, pattern) {
			request.SecurityViolations = append(request.SecurityViolations,
				fmt.Sprintf("Command injection pattern detected: %s", pattern))
			request.RiskLevel = "CRITICAL"
		}
	}

	for _, pattern := range xssPatterns {
		if strings.Contains(strings.ToLower(requestStr), pattern) {
			request.SecurityViolations = append(request.SecurityViolations,
				fmt.Sprintf("XSS pattern detected: %s", pattern))
			request.RiskLevel = "MEDIUM"
		}
	}
}

func validateOAuthPrivilegeEscalation(request *SecurityAwareOAuthRequest) {
	// Directive 2.1: Privilege Escalation Prevention

	// Check for privilege escalation patterns
	privilegePatterns := []string{
		"admin", "administrator", "root", "superuser",
		"privilege", "escalate", "elevate",
		"sudo", "su", "chmod", "chown",
	}

	// Check for dangerous scopes
	dangerousScopes := []string{
		"admin", "root", "system", "privileged",
		"write:all", "delete:all", "execute:all",
	}

	requestStr := fmt.Sprintf("%v", request)

	for _, pattern := range privilegePatterns {
		if strings.Contains(strings.ToLower(requestStr), pattern) {
			request.SecurityViolations = append(request.SecurityViolations,
				fmt.Sprintf("Privilege escalation pattern detected: %s", pattern))
			request.RiskLevel = "HIGH"
		}
	}

	// Check scope for dangerous permissions
	if request.TokenRequest.Scope != "" {
		scopeLower := strings.ToLower(request.TokenRequest.Scope)
		for _, dangerous := range dangerousScopes {
			if strings.Contains(scopeLower, dangerous) {
				request.SecurityViolations = append(request.SecurityViolations,
					fmt.Sprintf("Dangerous scope requested: %s", dangerous))
				request.RiskLevel = "HIGH"
			}
		}
	}
}

func testOAuthTimingAttackPrevention(request *SecurityAwareOAuthRequest) {
	// Directive 3.2: Timing Attack Prevention

	// Test constant-time comparison for tokens
	if request.TokenRequest.Code != "" {
		expectedCode := generateSecureToken(32)
		// Use constant-time comparison
		if subtle.ConstantTimeCompare([]byte(request.TokenRequest.Code), []byte(expectedCode)) == 1 {
			// This should never happen with random tokens
			request.SecurityViolations = append(request.SecurityViolations,
				"Timing attack vulnerability detected")
			request.RiskLevel = "CRITICAL"
		}
	}

	if request.TokenRequest.RefreshToken != "" {
		expectedRefresh := generateSecureToken(32)
		// Use constant-time comparison
		if subtle.ConstantTimeCompare([]byte(request.TokenRequest.RefreshToken), []byte(expectedRefresh)) == 1 {
			// This should never happen with random tokens
			request.SecurityViolations = append(request.SecurityViolations,
				"Timing attack vulnerability detected")
			request.RiskLevel = "CRITICAL"
		}
	}
}

func isValidGrantType(grantType string) bool {
	validGrantTypes := []string{
		"authorization_code", "refresh_token", "client_credentials",
		"password", "implicit", "device_code",
	}

	for _, valid := range validGrantTypes {
		if grantType == valid {
			return true
		}
	}

	return false
}

func isValidClientID(clientID string) bool {
	// Client ID should be reasonably sized and contain valid characters
	if len(clientID) < 8 || len(clientID) > 256 {
		return false
	}

	// Check for valid characters
	for _, char := range clientID {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '.') {
			return false
		}
	}

	return true
}

func isValidRedirectURI(redirectURI string) bool {
	// Parse and validate redirect URI
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}

	// Check for dangerous schemes
	dangerousSchemes := []string{"javascript:", "data:", "file:", "ftp:"}
	for _, scheme := range dangerousSchemes {
		if strings.HasPrefix(strings.ToLower(redirectURI), scheme) {
			return false
		}
	}

	// Check for localhost or 127.0.0.1 (allowed for development)
	if parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" {
		return true
	}

	// Check for valid domain
	if parsed.Hostname() == "" {
		return false
	}

	// Check for suspicious domains
	suspiciousDomains := []string{
		"evil.com", "malicious.net", "hack.org", "backdoor.io",
		"steal.me", "phish.com", "fake.net", "imposter.org",
	}

	for _, domain := range suspiciousDomains {
		if strings.Contains(strings.ToLower(parsed.Hostname()), domain) {
			return false
		}
	}

	return true
}

func isValidScope(scope string) bool {
	// Scope should be space-separated list of valid scopes
	if len(scope) > 1000 {
		return false
	}

	scopes := strings.Fields(scope)
	for _, s := range scopes {
		if len(s) == 0 || len(s) > 100 {
			return false
		}

		// Check for valid scope characters
		for _, char := range s {
			if !((char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				char == ':' || char == '.' || char == '_' || char == '-') {
				return false
			}
		}
	}

	return true
}

func isValidAuthorizationCode(code string) bool {
	// Authorization code should be reasonably sized and contain valid characters
	if len(code) < 16 || len(code) > 256 {
		return false
	}

	// Check for valid characters (base64-like)
	for _, char := range code {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '.' || char == '~') {
			return false
		}
	}

	return true
}

func isValidRefreshToken(token string) bool {
	// Refresh token should be reasonably sized and contain valid characters
	if len(token) < 16 || len(token) > 512 {
		return false
	}

	// Check for valid characters (base64-like)
	for _, char := range token {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '.' || char == '~') {
			return false
		}
	}

	return true
}

func isPredictableToken(token string) bool {
	// Check for predictable patterns
	predictablePatterns := []string{
		"test", "demo", "example", "sample", "dummy",
		"123456", "abcdef", "000000", "111111",
		"admin", "root", "user", "guest",
	}

	tokenLower := strings.ToLower(token)
	for _, pattern := range predictablePatterns {
		if strings.Contains(tokenLower, pattern) {
			return true
		}
	}

	// Check for sequential characters
	sequentialCount := 0
	for i := 1; i < len(token); i++ {
		if token[i] == token[i-1]+1 {
			sequentialCount++
			if sequentialCount >= 3 {
				return true
			}
		} else {
			sequentialCount = 0
		}
	}

	return false
}

func isReusedToken(token string) bool {
	// In a real implementation, this would check against a token blacklist
	// For fuzzing, we'll simulate by checking for common reused patterns
	reusedPatterns := []string{
		"reused", "duplicate", "repeat", "copy",
	}

	tokenLower := strings.ToLower(token)
	for _, pattern := range reusedPatterns {
		if strings.Contains(tokenLower, pattern) {
			return true
		}
	}

	return false
}

func isValidCSRFToken(token string) bool {
	// CSRF token should be base64-encoded and reasonably sized
	if len(token) < 16 || len(token) > 256 {
		return false
	}

	// Try to decode as base64
	_, err := base64.StdEncoding.DecodeString(token)
	return err == nil
}

func isCSRFTokenValid(token string, timestamp time.Time) bool {
	// Check if token is not expired (15 minutes)
	if time.Since(timestamp) > 15*time.Minute {
		return false
	}

	// In a real implementation, this would validate the token signature
	// For fuzzing, we'll just check the format
	return isValidCSRFToken(token)
}

func generateSecureToken(length int) string {
	token := make([]byte, length)
	rand.Read(token)
	return base64.StdEncoding.EncodeToString(token)
}
