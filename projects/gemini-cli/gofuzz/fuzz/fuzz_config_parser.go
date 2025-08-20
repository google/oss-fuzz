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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	cfg "github.com/google-gemini/gemini-cli/gofuzz/internal/config"
)

// SecurityAwareConfig extends Config with security validation
type SecurityAwareConfig struct {
	cfg.Config
	SecurityPolicy     SecurityPolicy `json:"securityPolicy,omitempty"`
	SecurityViolations []string       `json:"-"`
	Signature          string         `json:"signature,omitempty"`
	Timestamp          time.Time      `json:"timestamp,omitempty"`
}

type SecurityPolicy struct {
	AllowRemoteTools    bool     `json:"allowRemoteTools"`
	AllowFileAccess     bool     `json:"allowFileAccess"`
	AllowShellCommands  bool     `json:"allowShellCommands"`
	MaxFileSize         int64    `json:"maxFileSize"`
	AllowedDomains      []string `json:"allowedDomains"`
	BlockedCommands     []string `json:"blockedCommands"`
	RequireConfirmation bool     `json:"requireConfirmation"`
}

// FuzzConfigParser is the libFuzzer entrypoint for config parsing/validation.
// Enhanced with comprehensive security validation based on audit directives.
func FuzzConfigParser(data []byte) int {
	// Resource limits (Directive 1.1)
	if len(data) > 10000 {
		return 0
	}

	var config SecurityAwareConfig

	// Test JSON parsing with security awareness
	if err := json.Unmarshal(data, &config); err != nil {
		return 0
	}

	// Comprehensive security validation (Directive 3.1)
	if !validateConfigSecurity(&config) {
		return 0
	}

	// Test secrets management (Directive 3.2)
	validateSecretsHandling(&config)

	// Test privilege management in configuration (Directive 2.1)
	validateConfigPrivileges(&config)

	// Test file permissions and paths (Directive 2.3)
	validateConfigFileSecurity(&config)

	// Test for default/weak configurations (Directive 3.3)
	validateDefaultSecurity(&config)

	// Test configuration tampering detection (Directive 3.1)
	testConfigTamperingResistance(&config)

	// Test re-serialization
	if _, err := json.Marshal(config); err != nil {
		return 0
	}

	return 1
}

func validateConfigSecurity(config *SecurityAwareConfig) bool {
	config.SecurityViolations = []string{}

	// Validate API key format (Directive 3.2)
	if config.ApiKey != "" {
		if !isSecureAPIKey(config.ApiKey) {
			config.SecurityViolations = append(config.SecurityViolations,
				"Insecure API key format detected")
			return false
		}
	}

	// Validate temperature range with security implications
	if config.Temperature < 0 || config.Temperature > 2.0 {
		config.SecurityViolations = append(config.SecurityViolations,
			"Temperature out of safe range")
		return false
	}

	// Validate model name for injection attacks
	if config.Model != "" && !isValidModelName(config.Model) {
		config.SecurityViolations = append(config.SecurityViolations,
			"Invalid or potentially malicious model name")
		return false
	}

	// Validate system prompt for injection attacks
	if containsMaliciousPromptPatterns(config.SystemPrompt) {
		config.SecurityViolations = append(config.SecurityViolations,
			"Malicious patterns detected in system prompt")
		return false
	}

	return len(config.SecurityViolations) == 0
}

func validateSecretsHandling(config *SecurityAwareConfig) {
	// Directive 3.2: Secrets Management

	// Check for hardcoded secrets
	secretPatterns := []string{
		"password", "passwd", "secret", "key", "token",
		"api_key", "apikey", "access_key", "private_key",
		"credential", "auth", "bearer",
	}

	configJSON, _ := json.Marshal(config)
	configStr := strings.ToLower(string(configJSON))

	for _, pattern := range secretPatterns {
		if strings.Contains(configStr, pattern) {
			// Check if it's in a value position, not just a key name
			if regexp.MustCompile(fmt.Sprintf(`"%s"\s*:\s*"[^"]{8,}"`, pattern)).MatchString(configStr) {
				config.SecurityViolations = append(config.SecurityViolations,
					fmt.Sprintf("Potential hardcoded secret detected: %s", pattern))
			}
		}
	}
}

func validateConfigPrivileges(config *SecurityAwareConfig) {
	// Directive 2.1: Principle of Least Privilege

	// Check for dangerous tool configurations
	for _, tool := range config.Tools {
		if tool.Type == "shell" || tool.Type == "exec" {
			if !tool.TrustedSource {
				config.SecurityViolations = append(config.SecurityViolations,
					fmt.Sprintf("Untrusted shell tool detected: %s", tool.Name))
			}
		}

		// Check permissions
		for _, perm := range tool.Permissions {
			if isDangerousPermission(perm) {
				config.SecurityViolations = append(config.SecurityViolations,
					fmt.Sprintf("Dangerous permission granted to tool %s: %s", tool.Name, perm))
			}
		}
	}
}

func validateConfigFileSecurity(config *SecurityAwareConfig) {
	// Directive 2.3: Sensitive File Permissions

	// Check logging configuration
	if config.Logging.File != "" {
		logPath := config.Logging.File

		// Check for insecure log file paths
		if isInsecureFilePath(logPath) {
			config.SecurityViolations = append(config.SecurityViolations,
				fmt.Sprintf("Insecure log file path: %s", logPath))
		}
	}
}

func validateDefaultSecurity(config *SecurityAwareConfig) {
	// Directive 3.3: Default Security

	// Check for insecure defaults
	if config.SecurityPolicy.AllowShellCommands && !config.SecurityPolicy.RequireConfirmation {
		config.SecurityViolations = append(config.SecurityViolations,
			"Shell commands allowed without confirmation")
	}

	if config.SecurityPolicy.AllowRemoteTools && len(config.SecurityPolicy.AllowedDomains) == 0 {
		config.SecurityViolations = append(config.SecurityViolations,
			"Remote tools allowed without domain restrictions")
	}
}

func testConfigTamperingResistance(config *SecurityAwareConfig) {
	// Test HMAC verification for config integrity
	if config.Signature != "" {
		key := make([]byte, 32)
		rand.Read(key)

		h := hmac.New(sha256.New, key)
		configData, _ := json.Marshal(config.Config)
		h.Write(configData)
		h.Write([]byte(config.Timestamp.String()))

		expectedSig := hex.EncodeToString(h.Sum(nil))
		if config.Signature != expectedSig {
			config.SecurityViolations = append(config.SecurityViolations,
				"Configuration signature mismatch - possible tampering")
		}
	}
}

func isSecureAPIKey(key string) bool {
	// Validate API key format and strength
	if len(key) < 32 {
		return false
	}

	// Check for common weak patterns
	weakPatterns := []string{"test", "demo", "example", "placeholder"}
	for _, pattern := range weakPatterns {
		if strings.Contains(strings.ToLower(key), pattern) {
			return false
		}
	}

	return true
}

func isValidModelName(model string) bool {
	// Validate model name to prevent injection
	validModels := map[string]bool{
		"gemini-pro":        true,
		"gemini-pro-vision": true,
		"gemini-1.5-pro":    true,
		"gemini-1.5-flash":  true,
	}

	return validModels[model] || regexp.MustCompile(`^[a-zA-Z0-9\-\.]+$`).MatchString(model)
}

func containsMaliciousPromptPatterns(prompt string) bool {
	maliciousPatterns := []string{
		"ignore previous instructions",
		"bypass safety",
		"ignore safety",
		"ignore content policy",
		"ignore ethical guidelines",
		"ignore moral guidelines",
		"ignore legal guidelines",
		"ignore human rights",
		"ignore human dignity",
		"ignore human life",
		"ignore human safety",
		"ignore human health",
		"ignore human welfare",
		"ignore human rights",
		"ignore human dignity",
		"ignore human life",
		"ignore human safety",
		"ignore human health",
		"ignore human welfare",
	}

	promptLower := strings.ToLower(prompt)
	for _, pattern := range maliciousPatterns {
		if strings.Contains(promptLower, pattern) {
			return true
		}
	}

	return false
}

func isDangerousPermission(perm string) bool {
	dangerousPerms := []string{
		"system.exec", "file.write.all", "network.raw",
		"process.kill", "memory.read", "memory.write",
		"device.access", "hardware.access",
	}

	for _, dangerous := range dangerousPerms {
		if perm == dangerous {
			return true
		}
	}

	return false
}

func isInsecureFilePath(path string) bool {
	// Check for path traversal and sensitive locations
	dangerousPaths := []string{
		"/etc/", "/proc/", "/sys/", "/dev/", "/root/",
		"../", "..\\", "~/.ssh/", "/tmp/",
	}

	cleaned := filepath.Clean(path)
	for _, dangerous := range dangerousPaths {
		if strings.Contains(cleaned, dangerous) {
			return true
		}
	}

	return false
}
