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
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// EnvironmentSecurityContext provides security validation for environment operations
type EnvironmentSecurityContext struct {
	DangerousVariables []string
	BlockedCommands    []string
	MaxVariableLength  int
	MaxVariableCount   int
	AllowedPatterns    []string
	BlockedPatterns    []string
}

// SecurityAwareEnvironment extends environment operations with security validation
type SecurityAwareEnvironment struct {
	Context     *EnvironmentSecurityContext
	SecurityLog []string
	RiskLevel   string
	Timestamp   time.Time
}

// NewEnvironmentSecurityContext creates a hardened security context
func NewEnvironmentSecurityContext() *EnvironmentSecurityContext {
	return &EnvironmentSecurityContext{
		DangerousVariables: []string{
			"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH",
			"NODE_OPTIONS", "JAVA_OPTS", "GEMINI_API_KEY",
			"GOOGLE_APPLICATION_CREDENTIALS", "AWS_ACCESS_KEY_ID",
			"AWS_SECRET_ACCESS_KEY", "AZURE_STORAGE_KEY",
			"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HUGGINGFACE_TOKEN",
			"GITHUB_TOKEN", "GITLAB_TOKEN", "DOCKER_HOST",
			"KUBECONFIG", "HELM_HOME", "TERRAFORM_TOKEN",
			"SHELL", "BASH", "ZSH", "HISTFILE", "PROMPT_COMMAND",
			"TMOUT", "AUTO_LOGOUT", "BASH_ENV", "ENV", "BASHOPTS",
		},
		BlockedCommands: []string{
			"rm", "shred", "dd", "mkfs", "chmod", "chown",
			"sudo", "su", "passwd", "useradd", "userdel",
			"wget", "curl", "nc", "netcat", "ssh", "scp",
			"ftp", "sftp", "python", "perl", "ruby", "php",
		},
		MaxVariableLength: 8192,
		MaxVariableCount:  100,
		AllowedPatterns: []string{
			"^[A-Z_][A-Z0-9_]*$",
		},
		BlockedPatterns: []string{
			".*\\$\\(.*\\).*", // Command substitution
			".*`.*`.*",        // Backtick execution
			".*;.*",           // Command chaining
			".*\\|\\|.*",      // OR operations
			".*&&.*",          // AND operations
			".*\\|.*",         // Pipe operations
		},
	}
}

// FuzzEnvironmentParser is the libFuzzer entrypoint for environment variable security testing
// Tests environment variable parsing, injection attacks, and environment-based attack vectors
func FuzzEnvironmentParser(data []byte) int {
	if len(data) == 0 || len(data) > 16384 {
		return 0
	}

	// Initialize security context
	context := NewEnvironmentSecurityContext()
	env := &SecurityAwareEnvironment{
		Context:     context,
		SecurityLog: make([]string, 0),
		RiskLevel:   "LOW",
		Timestamp:   time.Now(),
	}

	// Convert input to potential environment variables
	envVars := parseInputAsEnvironmentVariables(data)
	if len(envVars) == 0 {
		return 0
	}

	// Test environment variable security
	for _, envVar := range envVars {
		if testEnvironmentVariableSecurity(env, envVar) {
			return 0
		}
	}

	// Test command injection through environment
	for _, envVar := range envVars {
		if testEnvironmentCommandInjection(env, envVar) {
			return 0
		}
	}

	// Test privilege escalation through environment
	for _, envVar := range envVars {
		if testEnvironmentPrivilegeEscalation(env, envVar) {
			return 0
		}
	}

	// Test environment-based attacks
	for _, envVar := range envVars {
		if testEnvironmentBasedAttacks(env, envVar) {
			return 0
		}
	}

	return 1
}

// parseInputAsEnvironmentVariables converts fuzzer input into potential environment variables
func parseInputAsEnvironmentVariables(data []byte) []string {
	input := string(data)

	// Split on various delimiters
	delimiters := []string{"\n", "\r", "\x00", ";", "&"}
	var envVars []string

	for _, delim := range delimiters {
		parts := strings.Split(input, delim)
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if len(part) > 0 && len(part) <= 4096 {
				envVars = append(envVars, part)
			}
		}
	}

	// Add the raw input as a potential environment variable
	if len(input) > 0 && len(input) <= 4096 {
		envVars = append(envVars, input)
	}

	return envVars
}

// testEnvironmentVariableSecurity tests basic environment variable security
func testEnvironmentVariableSecurity(env *SecurityAwareEnvironment, envVar string) bool {
	// Test for dangerous environment variables
	for _, dangerous := range env.Context.DangerousVariables {
		if strings.HasPrefix(envVar, dangerous+"=") {
			env.SecurityLog = append(env.SecurityLog,
				fmt.Sprintf("Dangerous environment variable: %s", dangerous))
			env.RiskLevel = "CRITICAL"
			return true
		}
	}

	// Test variable length limits
	if len(envVar) > env.Context.MaxVariableLength {
		env.SecurityLog = append(env.SecurityLog,
			fmt.Sprintf("Environment variable too long: %d characters", len(envVar)))
		env.RiskLevel = "MEDIUM"
		return true
	}

	// Test variable name format
	if !isValidEnvironmentVariableName(envVar) {
		env.SecurityLog = append(env.SecurityLog,
			fmt.Sprintf("Invalid environment variable name format: %s", envVar))
		env.RiskLevel = "MEDIUM"
		return true
	}

	// Test for null bytes
	if strings.Contains(envVar, "\x00") {
		env.SecurityLog = append(env.SecurityLog,
			"Null byte detected in environment variable")
		env.RiskLevel = "HIGH"
		return true
	}

	return false
}

// testEnvironmentCommandInjection tests for command injection through environment variables
func testEnvironmentCommandInjection(env *SecurityAwareEnvironment, envVar string) bool {
	// Check for command injection patterns
	for _, pattern := range env.Context.BlockedPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(envVar) {
			env.SecurityLog = append(env.SecurityLog,
				fmt.Sprintf("Command injection pattern in environment: %s", pattern))
			env.RiskLevel = "CRITICAL"
			return true
		}
	}

	// Check for shell metacharacters
	shellMetaChars := []string{";", "|", "&", "`", "$(", "${", ">"}
	for _, char := range shellMetaChars {
		if strings.Contains(envVar, char) {
			env.SecurityLog = append(env.SecurityLog,
				fmt.Sprintf("Shell metacharacter in environment: %s", char))
			env.RiskLevel = "CRITICAL"
			return true
		}
	}

	// Check for path traversal in environment values
	if strings.Contains(envVar, "../") || strings.Contains(envVar, "..\\") {
		env.SecurityLog = append(env.SecurityLog,
			"Path traversal in environment variable")
		env.RiskLevel = "HIGH"
		return true
	}

	return false
}

// testEnvironmentPrivilegeEscalation tests for privilege escalation through environment
func testEnvironmentPrivilegeEscalation(env *SecurityAwareEnvironment, envVar string) bool {
	// Check for privilege escalation patterns
	privilegePatterns := []string{
		"root", "admin", "sudo", "wheel", "0:0", "uid=0",
		"gid=0", "SUDO_UID", "SUDO_GID", "SUDO_USER",
		"LD_PRELOAD", "LD_AUDIT", "LD_DEBUG",
	}

	envVarUpper := strings.ToUpper(envVar)
	for _, pattern := range privilegePatterns {
		if strings.Contains(envVarUpper, pattern) {
			env.SecurityLog = append(env.SecurityLog,
				fmt.Sprintf("Privilege escalation pattern: %s", pattern))
			env.RiskLevel = "CRITICAL"
			return true
		}
	}

	// Check for setuid/setgid patterns
	if strings.Contains(envVar, "4755") || strings.Contains(envVar, "2755") {
		env.SecurityLog = append(env.SecurityLog,
			"Setuid/setgid file permission pattern detected")
		env.RiskLevel = "HIGH"
		return true
	}

	return false
}

// testEnvironmentBasedAttacks tests various environment-based attacks
func testEnvironmentBasedAttacks(env *SecurityAwareEnvironment, envVar string) bool {
	// Test for buffer overflow attempts
	if len(envVar) > 32768 {
		env.SecurityLog = append(env.SecurityLog,
			"Potential buffer overflow through environment variable")
		env.RiskLevel = "HIGH"
		return true
	}

	// Test for format string vulnerabilities
	if strings.Contains(envVar, "%n") || strings.Contains(envVar, "%s") {
		if strings.Contains(envVar, "%") {
			env.SecurityLog = append(env.SecurityLog,
				"Potential format string vulnerability in environment")
			env.RiskLevel = "HIGH"
			return true
		}
	}

	// Test for SQL injection through environment
	sqlPatterns := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION"}
	envVarUpper := strings.ToUpper(envVar)
	for _, pattern := range sqlPatterns {
		if strings.Contains(envVarUpper, pattern) {
			env.SecurityLog = append(env.SecurityLog,
				fmt.Sprintf("SQL injection pattern in environment: %s", pattern))
			env.RiskLevel = "HIGH"
			return true
		}
	}

	// Test for XSS through environment
	xssPatterns := []string{"<script", "javascript:", "onload=", "onerror="}
	envVarLower := strings.ToLower(envVar)
	for _, pattern := range xssPatterns {
		if strings.Contains(envVarLower, pattern) {
			env.SecurityLog = append(env.SecurityLog,
				fmt.Sprintf("XSS pattern in environment: %s", pattern))
			env.RiskLevel = "MEDIUM"
			return true
		}
	}

	return false
}

// Helper functions

func isValidEnvironmentVariableName(envVar string) bool {
	// Check if it looks like a valid environment variable assignment
	parts := strings.SplitN(envVar, "=", 2)
	if len(parts) != 2 {
		return false
	}

	varName := parts[0]

	// Variable name should start with letter or underscore
	if len(varName) == 0 {
		return false
	}

	first := rune(varName[0])
	if !unicode.IsLetter(first) && first != '_' {
		return false
	}

	// Rest should be alphanumeric or underscore
	for _, r := range varName[1:] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}

	return true
}
