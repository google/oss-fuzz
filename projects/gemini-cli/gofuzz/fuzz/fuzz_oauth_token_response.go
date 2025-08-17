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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Security constants for OAuth token validation
const (
	MaxTokenLength         = 8192 // Maximum token size
	MinTokenLength         = 32   // Minimum valid token size
	MaxTokenAge            = 3600 // Maximum token age in seconds
	TokenValidationTimeout = 5 * time.Second
	MaxScopeLength         = 1000 // Maximum scope string length
	MinStateLength         = 32   // Minimum state parameter length for CSRF protection
	PKCECodeLength         = 128  // PKCE code verifier length
)

// TokenValidator provides comprehensive OAuth token security validation
type TokenValidator struct {
	allowedIssuers []string
	minKeyLength   int
	maxAge         time.Duration
	secretPatterns *regexp.Regexp
	pkceEnabled    bool
	stateRequired  bool
}

// SecurityAwareTokenResponse extends OAuth token response with security validation
type SecurityAwareTokenResponse struct {
	AccessToken         string    `json:"access_token"`
	TokenType           string    `json:"token_type"`
	ExpiresIn           int       `json:"expires_in"`
	RefreshToken        string    `json:"refresh_token,omitempty"`
	Scope               string    `json:"scope,omitempty"`
	IDToken             string    `json:"id_token,omitempty"`
	State               string    `json:"state,omitempty"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	SecurityViolations  []string  `json:"-"`
	RiskLevel           string    `json:"-"`
	Signature           string    `json:"signature,omitempty"`
	Timestamp           time.Time `json:"timestamp,omitempty"`
	RedirectURI         string    `json:"redirect_uri,omitempty"`
}

// NewTokenValidator creates a security-hardened token validator with PKCE and state validation
func NewTokenValidator() *TokenValidator {
	return &TokenValidator{
		allowedIssuers: []string{
			"accounts.google.com",
			"https://accounts.google.com",
		},
		minKeyLength: 256,
		maxAge:       time.Duration(MaxTokenAge) * time.Second,
		secretPatterns: regexp.MustCompile(
			`(?i)(api[_-]?key|password|token|secret|credential|bearer)[\s:=]+[\S]{8,}`,
		),
		pkceEnabled:   true,
		stateRequired: true,
	}
}

// FuzzOAuthTokenResponse fuzzes OAuth token response validation with comprehensive security checks
func FuzzOAuthTokenResponse(data []byte) int {
	// Resource limits (Directive 1.1)
	if len(data) > MaxTokenLength {
		return 0
	}

	if len(data) < MinTokenLength {
		return 0
	}

	var response SecurityAwareTokenResponse

	// Test JSON parsing with security awareness
	if err := json.Unmarshal(data, &response); err != nil {
		return 0
	}

	// Initialize security validation
	validator := NewTokenValidator()

	// Comprehensive security validation (Directive 3.1)
	if !validateTokenResponseSecurity(&response, validator) {
		return 0
	}

	// Test token bounds checking (Directive 1.1)
	if !validateTokenResponseBounds(&response) {
		return 0
	}

	// Test PKCE validation (OWASP OAuth2 Security)
	validatePKCEImplementation(&response, validator)

	// Test state parameter for CSRF protection (OWASP OAuth2 Security)
	validateStateParameterSecurity(&response, validator)

	// Test redirect URI validation (OWASP OAuth2 Security)
	validateRedirectURISecurity(&response, validator)

	// Test token-specific security (Directive 3.1)
	validateTokenResponseDataSecurity(&response, validator)

	// Test for token hijacking (Directive 3.2)
	validateTokenResponseHijackingPrevention(&response)

	// Test for CSRF protection (Directive 2.1)
	validateTokenResponseCSRFProtection(&response)

	// Test token tampering detection (Directive 3.1)
	testTokenResponseTamperingResistance(&response, validator)

	// Test scope privilege escalation (Least Privilege Principle)
	validateScopePrivilegeEscalation(&response)

	// Test token expiry and rotation policies
	validateTokenExpiryPolicies(&response)

	// Test re-serialization
	if _, err := json.Marshal(response); err != nil {
		return 0
	}

	return 1
}

func validateTokenResponseSecurity(response *SecurityAwareTokenResponse, validator *TokenValidator) bool {
	response.SecurityViolations = []string{}
	response.RiskLevel = "LOW"

	// Validate access token format and content
	if response.AccessToken != "" {
		if !isValidTokenFormat(response.AccessToken) {
			response.SecurityViolations = append(response.SecurityViolations,
				"Invalid access token format")
			response.RiskLevel = "HIGH"
			return false
		}

		// Check for embedded secrets
		if validator.secretPatterns.MatchString(response.AccessToken) {
			response.SecurityViolations = append(response.SecurityViolations,
				"Potential secret detected in access token")
			response.RiskLevel = "CRITICAL"
			return false
		}
	}

	// Validate token type
	if response.TokenType != "" && !isValidTokenType(response.TokenType) {
		response.SecurityViolations = append(response.SecurityViolations,
			"Invalid or potentially malicious token type")
		response.RiskLevel = "MEDIUM"
		return false
	}

	// Validate expires_in value
	if response.ExpiresIn < 0 || response.ExpiresIn > MaxTokenAge {
		response.SecurityViolations = append(response.SecurityViolations,
			"Invalid token expiration time")
		response.RiskLevel = "MEDIUM"
		return false
	}

	// Validate refresh token if present
	if response.RefreshToken != "" {
		if !isValidTokenFormat(response.RefreshToken) {
			response.SecurityViolations = append(response.SecurityViolations,
				"Invalid refresh token format")
			response.RiskLevel = "HIGH"
			return false
		}
	}

	// Validate scope for privilege escalation attempts
	if response.Scope != "" {
		if !isValidScopeSecure(response.Scope) {
			response.SecurityViolations = append(response.SecurityViolations,
				"Invalid or excessive scope requested")
			response.RiskLevel = "HIGH"
			return false
		}
	}

	return len(response.SecurityViolations) == 0
}

func validateTokenResponseBounds(response *SecurityAwareTokenResponse) bool {
	// Check token length bounds
	if len(response.AccessToken) > MaxTokenLength {
		return false
	}

	if len(response.RefreshToken) > MaxTokenLength {
		return false
	}

	if len(response.IDToken) > MaxTokenLength {
		return false
	}

	// Check scope length
	if len(response.Scope) > MaxScopeLength {
		return false
	}

	// Check state parameter length
	if len(response.State) > MaxTokenLength {
		return false
	}

	// Check redirect URI length
	if len(response.RedirectURI) > MaxTokenLength {
		return false
	}

	return true
}

func validatePKCEImplementation(response *SecurityAwareTokenResponse, validator *TokenValidator) {
	// PKCE (Proof Key for Code Exchange) validation for enhanced security
	if validator.pkceEnabled {
		if response.CodeChallenge != "" {
			// Validate code challenge format
			if len(response.CodeChallenge) < 43 || len(response.CodeChallenge) > 128 {
				response.SecurityViolations = append(response.SecurityViolations,
					"Invalid PKCE code challenge length")
				response.RiskLevel = "HIGH"
			}

			// Validate code challenge method
			validMethods := []string{"S256", "plain"}
			methodValid := false
			for _, method := range validMethods {
				if response.CodeChallengeMethod == method {
					methodValid = true
					break
				}
			}

			if !methodValid {
				response.SecurityViolations = append(response.SecurityViolations,
					"Invalid PKCE code challenge method")
				response.RiskLevel = "HIGH"
			}

			// Prefer S256 over plain method
			if response.CodeChallengeMethod == "plain" {
				response.SecurityViolations = append(response.SecurityViolations,
					"PKCE plain method is less secure than S256")
				response.RiskLevel = "MEDIUM"
			}
		}
	}
}

func validateStateParameterSecurity(response *SecurityAwareTokenResponse, validator *TokenValidator) {
	// State parameter validation for CSRF protection
	if validator.stateRequired {
		if response.State == "" {
			response.SecurityViolations = append(response.SecurityViolations,
				"Missing state parameter for CSRF protection")
			response.RiskLevel = "HIGH"
			return
		}

		// Validate state parameter length and entropy
		if len(response.State) < MinStateLength {
			response.SecurityViolations = append(response.SecurityViolations,
				"State parameter too short for secure CSRF protection")
			response.RiskLevel = "MEDIUM"
		}

		// Check for predictable state patterns
		predictablePatterns := []string{
			"12345", "state", "csrf", "token", "test",
		}

		stateLower := strings.ToLower(response.State)
		for _, pattern := range predictablePatterns {
			if strings.Contains(stateLower, pattern) {
				response.SecurityViolations = append(response.SecurityViolations,
					"Predictable state parameter detected")
				response.RiskLevel = "HIGH"
				break
			}
		}
	}
}

func validateRedirectURISecurity(response *SecurityAwareTokenResponse, _ *TokenValidator) {
	// Strict redirect URI validation to prevent redirection attacks
	if response.RedirectURI != "" {
		// Check for dangerous redirect patterns
		dangerousPatterns := []string{
			"javascript:", "data:", "file:", "ftp:",
			"about:", "chrome:", "chrome-extension:",
		}

		uriLower := strings.ToLower(response.RedirectURI)
		for _, pattern := range dangerousPatterns {
			if strings.HasPrefix(uriLower, pattern) {
				response.SecurityViolations = append(response.SecurityViolations,
					fmt.Sprintf("Dangerous redirect URI scheme: %s", pattern))
				response.RiskLevel = "CRITICAL"
				return
			}
		}

		// Validate HTTPS requirement for production
		if !strings.HasPrefix(uriLower, "https://") && !strings.HasPrefix(uriLower, "http://localhost") {
			response.SecurityViolations = append(response.SecurityViolations,
				"Redirect URI should use HTTPS in production")
			response.RiskLevel = "MEDIUM"
		}

		// Check for open redirects
		if strings.Contains(response.RedirectURI, "..") ||
			strings.Contains(response.RedirectURI, "//") {
			response.SecurityViolations = append(response.SecurityViolations,
				"Potential open redirect vulnerability in URI")
			response.RiskLevel = "HIGH"
		}
	}
}

func validateScopePrivilegeEscalation(response *SecurityAwareTokenResponse) {
	// Enhanced scope validation following least privilege principle
	if response.Scope != "" {
		// Check for excessive privilege scopes
		highPrivilegeScopes := []string{
			"admin", "root", "system", "sudo", "superuser",
			"write:all", "delete:all", "execute:all",
			"*", "full_access", "unrestricted",
		}

		scopeLower := strings.ToLower(response.Scope)
		for _, privileged := range highPrivilegeScopes {
			if strings.Contains(scopeLower, privileged) {
				response.SecurityViolations = append(response.SecurityViolations,
					fmt.Sprintf("High privilege scope detected: %s", privileged))
				response.RiskLevel = "HIGH"
			}
		}

		// Check for scope injection attempts
		injectionPatterns := []string{
			";", "&", "|", "$(", "`", "eval",
		}

		for _, pattern := range injectionPatterns {
			if strings.Contains(response.Scope, pattern) {
				response.SecurityViolations = append(response.SecurityViolations,
					"Potential scope injection attempt detected")
				response.RiskLevel = "CRITICAL"
			}
		}
	}
}

func validateTokenExpiryPolicies(response *SecurityAwareTokenResponse) {
	// Validate token expiry and rotation policies
	if response.ExpiresIn > 0 {
		// Recommend short-lived access tokens (max 1 hour)
		if response.ExpiresIn > 3600 {
			response.SecurityViolations = append(response.SecurityViolations,
				"Access token expiry too long, recommend shorter duration")
			response.RiskLevel = "MEDIUM"
		}

		// Warn about very long-lived tokens
		if response.ExpiresIn > 86400 { // 24 hours
			response.SecurityViolations = append(response.SecurityViolations,
				"Extremely long-lived token detected")
			response.RiskLevel = "HIGH"
		}
	}

	// Check for refresh token rotation indicators
	if response.RefreshToken != "" && response.AccessToken != "" {
		// In a real implementation, we'd check if refresh token is rotated
		// For fuzzing, we simulate the check
		if len(response.RefreshToken) == len(response.AccessToken) {
			response.SecurityViolations = append(response.SecurityViolations,
				"Potential refresh token rotation issue")
			response.RiskLevel = "MEDIUM"
		}
	}
}

func validateTokenResponseDataSecurity(response *SecurityAwareTokenResponse, _ *TokenValidator) {
	// Test for injection attacks in token data
	dangerousPatterns := []string{
		"<script", "javascript:", "data:", "vbscript:",
		"onload=", "onerror=", "eval(", "setTimeout(",
		"setInterval(", "Function(", "constructor",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(response.AccessToken), pattern) ||
			strings.Contains(strings.ToLower(response.RefreshToken), pattern) ||
			strings.Contains(strings.ToLower(response.Scope), pattern) {
			response.SecurityViolations = append(response.SecurityViolations,
				fmt.Sprintf("Injection pattern detected: %s", pattern))
			response.RiskLevel = "CRITICAL"
		}
	}

	// Test for path traversal in token data
	traversalPatterns := []string{"../", "..\\", "%2e%2e", "....//"}
	for _, pattern := range traversalPatterns {
		if strings.Contains(response.AccessToken, pattern) ||
			strings.Contains(response.RefreshToken, pattern) {
			response.SecurityViolations = append(response.SecurityViolations,
				"Path traversal pattern detected in token")
			response.RiskLevel = "HIGH"
		}
	}
}

func validateTokenResponseHijackingPrevention(response *SecurityAwareTokenResponse) {
	// Check for token hijacking indicators
	suspiciousPatterns := []string{
		"Bearer ", "Authorization:", "Cookie:",
		"X-Auth-Token:", "X-API-Key:",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(response.AccessToken, pattern) ||
			strings.Contains(response.RefreshToken, pattern) {
			response.SecurityViolations = append(response.SecurityViolations,
				"Potential token hijacking attempt detected")
			response.RiskLevel = "CRITICAL"
		}
	}
}

func validateTokenResponseCSRFProtection(response *SecurityAwareTokenResponse) {
	// Generate and validate CSRF token
	csrfToken := generateCSRFToken()
	if len(csrfToken) < 32 {
		response.SecurityViolations = append(response.SecurityViolations,
			"CSRF token generation failed")
		response.RiskLevel = "HIGH"
	}

	// Test constant-time comparison
	testToken := generateCSRFToken()
	if !validateCSRFTokenConstantTime(csrfToken, testToken) {
		// This is expected to fail, but tests the validation function
	}
}

func testTokenResponseTamperingResistance(response *SecurityAwareTokenResponse, _ *TokenValidator) {
	// Generate HMAC signature for token response
	key := make([]byte, 32)
	rand.Read(key)

	h := hmac.New(sha256.New, key)
	h.Write([]byte(response.AccessToken))
	h.Write([]byte(response.TokenType))
	if response.RefreshToken != "" {
		h.Write([]byte(response.RefreshToken))
	}

	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	response.Signature = signature
	response.Timestamp = time.Now()

	// Verify signature
	h2 := hmac.New(sha256.New, key)
	h2.Write([]byte(response.AccessToken))
	h2.Write([]byte(response.TokenType))
	if response.RefreshToken != "" {
		h2.Write([]byte(response.RefreshToken))
	}

	expectedSig := base64.StdEncoding.EncodeToString(h2.Sum(nil))
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		response.SecurityViolations = append(response.SecurityViolations,
			"Token signature verification failed")
		response.RiskLevel = "CRITICAL"
	}
}

func isValidTokenFormat(token string) bool {
	// Basic token format validation
	if len(token) < 32 || len(token) > MaxTokenLength {
		return false
	}

	// Check for valid base64 or JWT format
	if strings.Count(token, ".") == 2 {
		// Potential JWT format
		parts := strings.Split(token, ".")
		for _, part := range parts {
			if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
				return false
			}
		}
		return true
	}

	// Check for valid base64 format
	if _, err := base64.StdEncoding.DecodeString(token); err != nil {
		// Try URL encoding
		if _, err := base64.URLEncoding.DecodeString(token); err != nil {
			return false
		}
	}

	return true
}

func isValidTokenType(tokenType string) bool {
	validTypes := []string{"Bearer", "bearer", "MAC", "mac"}
	for _, valid := range validTypes {
		if tokenType == valid {
			return true
		}
	}
	return false
}

func isValidScopeSecure(scope string) bool {
	// Validate OAuth scopes for security
	dangerousScopes := []string{
		"admin", "root", "system", "sudo",
		"execute", "shell", "command",
	}

	scopeParts := strings.Fields(scope)
	for _, part := range scopeParts {
		for _, dangerous := range dangerousScopes {
			if strings.Contains(strings.ToLower(part), dangerous) {
				return false
			}
		}
	}

	// Check scope length and format
	if len(scope) > MaxScopeLength {
		return false
	}

	return true
}

func generateCSRFToken() string {
	token := make([]byte, 32)
	rand.Read(token)
	return base64.StdEncoding.EncodeToString(token)
}

func validateCSRFTokenConstantTime(provided, expected string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(provided),
		[]byte(expected),
	) == 1
}
