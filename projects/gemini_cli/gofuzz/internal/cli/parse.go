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

package cli

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Security constants for resource limits and attack prevention
const (
	MaxInputLength    = 10000
	MaxTokenCount     = 1000
	MaxArguments      = 100
	MaxArgumentLength = 1000
	MaxExecutionTime  = 30 * time.Second
)

// RiskLevel defines security risk classification
type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

// SecurityViolation tracks detected security issues
type SecurityViolation struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Risk        RiskLevel `json:"risk"`
	Timestamp   time.Time `json:"timestamp"`
	Pattern     string    `json:"pattern,omitempty"`
}

// CommandSanitizer provides comprehensive command injection prevention
type CommandSanitizer struct {
	blockedPatterns []string
	allowedCommands map[string]bool
	blockedCommands map[string]bool
	violations      []SecurityViolation
	secretPatterns  *regexp.Regexp
}

// NewCommandSanitizer creates a security-hardened command sanitizer
func NewCommandSanitizer() *CommandSanitizer {
	return &CommandSanitizer{
		blockedPatterns: []string{
			// Shell metacharacters for command injection
			";", "|", "&", "||", "&&", "`", "$(", "${", ">", "<", ">>", "<<",
			"(", ")", "{", "}", "[", "]", "\\", "'", "\"", "~", "!", "#",
			// Command substitution patterns
			"eval", "exec", "system", "shell_exec",
			// Redirection patterns
			"2>", "2>>", "&>", "&>>",
			// Path traversal patterns
			"../", "..\\", "..", "/etc/", "/proc/", "/sys/",
			// Environment variable injection
			"LD_PRELOAD", "PATH=", "NODE_OPTIONS",
		},
		allowedCommands: map[string]bool{
			"gemini": true,
			"help":   true,
			"config": true,
			"auth":   true,
		},
		blockedCommands: map[string]bool{
			"rm":     true,
			"sudo":   true,
			"su":     true,
			"chmod":  true,
			"chown":  true,
			"passwd": true,
			"sh":     true,
			"bash":   true,
			"zsh":    true,
			"curl":   true,
			"wget":   true,
		},
		violations: make([]SecurityViolation, 0),
		secretPatterns: regexp.MustCompile(
			`(?i)(api[_-]?key|password|token|secret|credential|bearer)[\s:=]+[\S]{8,}`,
		),
	}
}

// Validate performs comprehensive security validation on input
func (cs *CommandSanitizer) Validate(input string) error {
	// Check for blocked patterns
	for _, pattern := range cs.blockedPatterns {
		if strings.Contains(strings.ToLower(input), strings.ToLower(pattern)) {
			violation := SecurityViolation{
				Type:        "command_injection",
				Description: fmt.Sprintf("Blocked pattern detected: %s", pattern),
				Risk:        RiskCritical,
				Timestamp:   time.Now(),
				Pattern:     pattern,
			}
			cs.violations = append(cs.violations, violation)
			return fmt.Errorf("security violation: blocked pattern detected: %s", pattern)
		}
	}

	// Check for null bytes
	if strings.Contains(input, "\x00") {
		violation := SecurityViolation{
			Type:        "null_byte_injection",
			Description: "Null byte detected in input",
			Risk:        RiskHigh,
			Timestamp:   time.Now(),
		}
		cs.violations = append(cs.violations, violation)
		return errors.New("security violation: null byte injection detected")
	}

	// Check for terminal escape sequences
	if containsTerminalEscapes(input) {
		violation := SecurityViolation{
			Type:        "terminal_escape",
			Description: "Terminal escape sequence detected",
			Risk:        RiskMedium,
			Timestamp:   time.Now(),
		}
		cs.violations = append(cs.violations, violation)
		return errors.New("security violation: terminal escape sequence detected")
	}

	// Check for secrets
	if cs.secretPatterns.MatchString(input) {
		violation := SecurityViolation{
			Type:        "secret_exposure",
			Description: "Potential secret detected in input",
			Risk:        RiskHigh,
			Timestamp:   time.Now(),
		}
		cs.violations = append(cs.violations, violation)
		return errors.New("security violation: potential secret detected")
	}

	return nil
}

// RedactSecrets removes sensitive information from input
func (cs *CommandSanitizer) RedactSecrets(input string) string {
	return cs.secretPatterns.ReplaceAllString(input, "$1=REDACTED")
}

// ValidateFilePath performs comprehensive path validation
func ValidateFilePath(path string) error {
	// Clean and validate path
	cleaned := filepath.Clean(path)

	// Check for traversal patterns
	if strings.Contains(cleaned, "..") {
		return errors.New("path traversal detected")
	}

	// Check for absolute paths to sensitive directories
	sensitivePaths := []string{
		"/etc/", "/proc/", "/sys/", "/dev/", "/root/",
		"/var/log/", "/var/run/", "/tmp/", "/boot/",
	}

	for _, sensPath := range sensitivePaths {
		if strings.HasPrefix(cleaned, sensPath) {
			return fmt.Errorf("access to sensitive path denied: %s", sensPath)
		}
	}

	// Verify path length
	if len(cleaned) > 4096 {
		return errors.New("path too long")
	}

	return nil
}

// containsTerminalEscapes checks for ANSI escape sequences
func containsTerminalEscapes(input string) bool {
	escapePatterns := []string{
		"\x1b[", "\x1b]", "\x07", "\x08", "\x0c", "\x0e", "\x0f",
		"\x1b(", "\x1b)", "\x1b*", "\x1b+", "\x1b-", "\x1b.",
	}

	for _, pattern := range escapePatterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}

	return false
}

// Minimal CLI argument parser mirror for fuzzing shell injection vectors.
// Based on common CLI patterns without actual execution.

type Command struct {
	Name               string
	Args               []string
	Flags              map[string]string
	Options            map[string]bool
	SecurityViolations []SecurityViolation
	RiskLevel          RiskLevel
	Signature          string
	Timestamp          time.Time
}

type ParseResult struct {
	Command   *Command
	Remaining []string
}

// ParseArgs mirrors CLI argument parsing logic for fuzzing.
// Focuses on injection-prone areas without actual execution.
func ParseArgs(args []string) (*ParseResult, error) {
	if len(args) == 0 {
		return nil, errors.New("no arguments provided")
	}

	// Prevent excessively long argument lists (Directive 1.1)
	if len(args) > MaxArguments {
		return nil, fmt.Errorf("too many arguments: %d exceeds limit of %d", len(args), MaxArguments)
	}

	// Initialize command sanitizer
	sanitizer := NewCommandSanitizer()

	cmd := &Command{
		Name:               args[0],
		Args:               []string{},
		Flags:              make(map[string]string),
		Options:            make(map[string]bool),
		SecurityViolations: []SecurityViolation{},
		RiskLevel:          RiskLow,
		Timestamp:          time.Now(),
	}

	// Basic validation of command name with security checks
	if err := validateCommandName(cmd.Name, sanitizer); err != nil {
		return nil, err
	}

	i := 1
	for i < len(args) {
		arg := args[i]

		// Prevent excessively long individual arguments (Directive 1.1)
		if len(arg) > MaxArgumentLength {
			return nil, fmt.Errorf("argument too long: %d exceeds limit of %d", len(arg), MaxArgumentLength)
		}

		// Security validation for each argument (Directive 3.1)
		if err := sanitizer.Validate(arg); err != nil {
			cmd.SecurityViolations = append(cmd.SecurityViolations, sanitizer.violations...)
			cmd.RiskLevel = RiskCritical
			return nil, fmt.Errorf("security validation failed for argument '%s': %v", sanitizer.RedactSecrets(arg), err)
		}

		if strings.HasPrefix(arg, "--") {
			// Long flag
			if err := parseLongFlag(arg, args, &i, cmd, sanitizer); err != nil {
				return nil, err
			}
		} else if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			// Short flag
			if err := parseShortFlag(arg, cmd, sanitizer); err != nil {
				return nil, err
			}
		} else {
			// Regular argument - validate for path traversal if it looks like a path
			if strings.Contains(arg, "/") || strings.Contains(arg, "\\") {
				if err := ValidateFilePath(arg); err != nil {
					violation := SecurityViolation{
						Type:        "path_traversal",
						Description: fmt.Sprintf("Invalid file path: %s", err.Error()),
						Risk:        RiskHigh,
						Timestamp:   time.Now(),
					}
					cmd.SecurityViolations = append(cmd.SecurityViolations, violation)
					cmd.RiskLevel = RiskHigh
					return nil, fmt.Errorf("path validation failed: %v", err)
				}
			}
			cmd.Args = append(cmd.Args, arg)
		}
		i++
	}

	// Generate security signature for tampering detection
	if err := generateSecuritySignature(cmd); err != nil {
		return nil, fmt.Errorf("failed to generate security signature: %v", err)
	}

	return &ParseResult{
		Command:   cmd,
		Remaining: []string{},
	}, nil
}

func validateCommandName(name string, sanitizer *CommandSanitizer) error {
	if len(name) == 0 {
		return errors.New("empty command name")
	}
	if len(name) > 256 {
		return errors.New("command name too long")
	}

	// Security validation using sanitizer (Directive 3.1)
	if err := sanitizer.Validate(name); err != nil {
		return fmt.Errorf("command name security validation failed: %v", err)
	}

	// Check if command is explicitly blocked
	if sanitizer.blockedCommands[strings.ToLower(name)] {
		return fmt.Errorf("command '%s' is blocked for security reasons", name)
	}

	// Validate Unicode characters for potential bypasses
	for _, r := range name {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return fmt.Errorf("non-printable character detected in command name")
		}
	}

	return nil
}

func parseLongFlag(arg string, args []string, i *int, cmd *Command, sanitizer *CommandSanitizer) error {
	parts := strings.SplitN(arg[2:], "=", 2)
	flagName := parts[0]

	if len(flagName) == 0 {
		return errors.New("empty flag name")
	}

	// Security validation for flag name
	if err := sanitizer.Validate(flagName); err != nil {
		return fmt.Errorf("flag name security validation failed: %v", err)
	}

	if len(parts) == 2 {
		// --flag=value
		flagValue := parts[1]

		// Security validation for flag value
		if err := sanitizer.Validate(flagValue); err != nil {
			return fmt.Errorf("flag value security validation failed: %v", err)
		}

		// Redact secrets in flag values
		cmd.Flags[flagName] = sanitizer.RedactSecrets(flagValue)
	} else {
		// --flag (boolean or next arg is value)
		if *i+1 < len(args) && !strings.HasPrefix(args[*i+1], "-") {
			*i++
			flagValue := args[*i]

			// Security validation for flag value
			if err := sanitizer.Validate(flagValue); err != nil {
				return fmt.Errorf("flag value security validation failed: %v", err)
			}

			cmd.Flags[flagName] = sanitizer.RedactSecrets(flagValue)
		} else {
			cmd.Options[flagName] = true
		}
	}

	return nil
}

func parseShortFlag(arg string, cmd *Command, sanitizer *CommandSanitizer) error {
	flags := arg[1:] // Remove leading -

	// Security validation for flag string
	if err := sanitizer.Validate(flags); err != nil {
		return fmt.Errorf("short flag security validation failed: %v", err)
	}

	for _, flag := range flags {
		flagStr := string(flag)

		// Validate individual flag character
		if !unicode.IsPrint(flag) {
			return fmt.Errorf("non-printable character in flag: %c", flag)
		}

		cmd.Options[flagStr] = true
	}

	return nil
}

// generateSecuritySignature creates HMAC signature for tampering detection
func generateSecuritySignature(cmd *Command) error {
	// Generate random key for this session (in production, use persistent key)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}

	// Create signature data
	h := hmac.New(sha256.New, key)
	h.Write([]byte(cmd.Name))
	h.Write([]byte(strings.Join(cmd.Args, "|")))
	h.Write([]byte(fmt.Sprintf("%v", cmd.Flags)))
	h.Write([]byte(fmt.Sprintf("%v", cmd.Options)))
	h.Write([]byte(cmd.Timestamp.String()))

	cmd.Signature = hex.EncodeToString(h.Sum(nil))
	return nil
}

// VerifySecuritySignature validates command integrity
func VerifySecuritySignature(cmd *Command, key []byte) error {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(cmd.Name))
	h.Write([]byte(strings.Join(cmd.Args, "|")))
	h.Write([]byte(fmt.Sprintf("%v", cmd.Flags)))
	h.Write([]byte(fmt.Sprintf("%v", cmd.Options)))
	h.Write([]byte(cmd.Timestamp.String()))

	expectedSig := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(cmd.Signature), []byte(expectedSig)) != 1 {
		return errors.New("command signature verification failed")
	}

	return nil
}
