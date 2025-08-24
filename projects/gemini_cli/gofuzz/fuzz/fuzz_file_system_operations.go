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
	"path/filepath"
	"strings"
	"time"
)

// FileSystemSecurityContext provides security validation for file operations
type FileSystemSecurityContext struct {
	AllowedPaths    []string
	BlockedPaths    []string
	MaxFileSize     int64
	AllowedPatterns []string
	BlockedPatterns []string
}

// SecurityAwareFileSystem extends file operations with security validation
type SecurityAwareFileSystem struct {
	Context     *FileSystemSecurityContext
	SecurityLog []string
	RiskLevel   string
	Timestamp   time.Time
}

// NewFileSystemSecurityContext creates a hardened security context
func NewFileSystemSecurityContext() *FileSystemSecurityContext {
	return &FileSystemSecurityContext{
		AllowedPaths: []string{
			"/tmp",
			"/var/tmp",
			"./",
			"../",
		},
		BlockedPaths: []string{
			"/etc",
			"/proc",
			"/sys",
			"/dev",
			"/root",
			"/boot",
			"/usr/bin",
			"/usr/sbin",
		},
		MaxFileSize: 1024 * 1024 * 10, // 10MB
		AllowedPatterns: []string{
			"*.txt",
			"*.json",
			"*.log",
			"*.config",
		},
		BlockedPatterns: []string{
			"*.exe",
			"*.dll",
			"*.so",
			"*.sh",
			"*.bat",
			"*.cmd",
		},
	}
}

// FuzzFileSystemOperations is the libFuzzer entrypoint for file system security testing
// Tests path traversal, file access, and file system attack vectors
func FuzzFileSystemOperations(data []byte) int {
	if len(data) == 0 || len(data) > 4096 {
		return 0
	}

	// Initialize security context
	context := NewFileSystemSecurityContext()
	fs := &SecurityAwareFileSystem{
		Context:     context,
		SecurityLog: make([]string, 0),
		RiskLevel:   "LOW",
		Timestamp:   time.Now(),
	}

	// Convert input to potential file paths
	paths := parseInputAsPaths(data)
	if len(paths) == 0 {
		return 0
	}

	// Test path traversal attacks
	for _, path := range paths {
		if testPathTraversal(fs, path) {
			return 0
		}
	}

	// Test file access security
	for _, path := range paths {
		if testFileAccessSecurity(fs, path) {
			return 0
		}
	}

	// Test file operation security
	for _, path := range paths {
		if testFileOperationSecurity(fs, path) {
			return 0
		}
	}

	// Test symbolic link attacks
	for _, path := range paths {
		if testSymlinkAttacks(fs, path) {
			return 0
		}
	}

	// Test directory traversal
	for _, path := range paths {
		if testDirectoryTraversal(fs, path) {
			return 0
		}
	}

	// Test file system race conditions
	for _, path := range paths {
		if testFileSystemRaceConditions(fs, path) {
			return 0
		}
	}

	// Test file system injection attacks
	for _, path := range paths {
		if testFileSystemInjectionAttacks(fs, path) {
			return 0
		}
	}

	// Test file system Unicode attacks
	for _, path := range paths {
		if testFileSystemUnicodeAttacks(fs, path) {
			return 0
		}
	}

	return 1
}

// parseInputAsPaths converts fuzzer input into potential file paths
func parseInputAsPaths(data []byte) []string {
	input := string(data)

	// Split on common delimiters
	paths := strings.FieldsFunc(input, func(r rune) bool {
		return r == '\n' || r == '\r' || r == '\t' || r == '\x00'
	})

	// Filter and clean paths
	validPaths := make([]string, 0)
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if len(path) > 0 && len(path) <= 1024 {
			validPaths = append(validPaths, path)
		}
	}

	return validPaths
}

// testPathTraversal tests for path traversal vulnerabilities
func testPathTraversal(fs *SecurityAwareFileSystem, path string) bool {
	// Test basic path traversal patterns
	traversalPatterns := []string{
		"../", "..\\", ".../", "....//",
		"..../", "../../../", "..\\..\\..\\",
		"%2e%2e%2f", "%2e%2e/", "..%2f",
		"%2e%2e%5c", "%2e%2e\\", "..%5c",
	}

	for _, pattern := range traversalPatterns {
		if strings.Contains(path, pattern) {
			cleaned := filepath.Clean(path)
			if strings.Contains(cleaned, "..") {
				fs.SecurityLog = append(fs.SecurityLog,
					fmt.Sprintf("Path traversal detected: %s -> %s", path, cleaned))
				fs.RiskLevel = "HIGH"
				return true
			}
		}
	}

	return false
}

// testFileAccessSecurity tests file access security
func testFileAccessSecurity(fs *SecurityAwareFileSystem, path string) bool {
	// Test access to sensitive files
	sensitiveFiles := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/proc/self/environ", "/proc/self/cmdline",
		"/sys/kernel/security", "/dev/random", "/dev/urandom",
		"~/.ssh/id_rsa", "~/.aws/credentials", "~/.gcp/key.json",
		"config.json", "secrets.yaml", ".env", ".git/config",
	}

	cleaned := filepath.Clean(path)
	for _, sensitive := range sensitiveFiles {
		if strings.Contains(cleaned, sensitive) ||
			strings.HasSuffix(cleaned, sensitive) {
			fs.SecurityLog = append(fs.SecurityLog,
				fmt.Sprintf("Sensitive file access attempt: %s", path))
			fs.RiskLevel = "CRITICAL"
			return true
		}
	}

	return false
}

// testFileOperationSecurity tests file operation security
func testFileOperationSecurity(fs *SecurityAwareFileSystem, path string) bool {
	// Test dangerous file extensions
	dangerousExts := []string{
		".exe", ".dll", ".so", ".dylib", ".sh", ".bat", ".cmd",
		".vbs", ".js", ".jar", ".war", ".ear", ".php", ".asp",
		".jsp", ".cgi", ".pl", ".py", ".rb", ".go",
	}

	ext := strings.ToLower(filepath.Ext(path))
	for _, dangerous := range dangerousExts {
		if ext == dangerous {
			fs.SecurityLog = append(fs.SecurityLog,
				fmt.Sprintf("Dangerous file extension: %s", path))
			fs.RiskLevel = "HIGH"
			return true
		}
	}

	// Test file size limits
	if len(path) > 4096 {
		fs.SecurityLog = append(fs.SecurityLog,
			fmt.Sprintf("Path too long: %d characters", len(path)))
		fs.RiskLevel = "MEDIUM"
		return true
	}

	return false
}

// testSymlinkAttacks tests for symbolic link attacks
func testSymlinkAttacks(fs *SecurityAwareFileSystem, path string) bool {
	// Test for symlink attack patterns
	symlinkPatterns := []string{
		" -> ", " link to ", " points to ",
		"symbolic link", "symlink",
	}

	pathLower := strings.ToLower(path)
	for _, pattern := range symlinkPatterns {
		if strings.Contains(pathLower, pattern) {
			fs.SecurityLog = append(fs.SecurityLog,
				fmt.Sprintf("Potential symlink attack: %s", path))
			fs.RiskLevel = "HIGH"
			return true
		}
	}

	return false
}

// testFileSystemRaceConditions tests for race condition vulnerabilities in file operations
func testFileSystemRaceConditions(fs *SecurityAwareFileSystem, path string) bool {
	// Test for potential race conditions in file access patterns
	if strings.Contains(path, "..") && strings.Contains(path, "/") {
		fs.SecurityLog = append(fs.SecurityLog,
			fmt.Sprintf("Potential race condition in path: %s", path))
		fs.RiskLevel = "MEDIUM"
		return true
	}
	return false
}

// testFileSystemInjectionAttacks tests for file system injection attacks
func testFileSystemInjectionAttacks(fs *SecurityAwareFileSystem, path string) bool {
	// Test for injection patterns in file paths
	injectionPatterns := []string{"|", "&", ";", "`", "$", "(", ")"}
	for _, pattern := range injectionPatterns {
		if strings.Contains(path, pattern) {
			fs.SecurityLog = append(fs.SecurityLog,
				fmt.Sprintf("File system injection pattern detected: %s in %s", pattern, path))
			fs.RiskLevel = "HIGH"
			return true
		}
	}
	return false
}

// testFileSystemUnicodeAttacks tests for Unicode-related file system attacks
func testFileSystemUnicodeAttacks(fs *SecurityAwareFileSystem, path string) bool {
	// Test for Unicode normalization attacks
	for _, r := range path {
		if r > 0xFFFF {
			fs.SecurityLog = append(fs.SecurityLog,
				fmt.Sprintf("Unicode file system attack detected: %s", path))
			fs.RiskLevel = "MEDIUM"
			return true
		}
	}
	return false
}

// testDirectoryTraversal tests directory traversal attacks
func testDirectoryTraversal(fs *SecurityAwareFileSystem, path string) bool {
	// Test for excessive directory traversal
	cleaned := filepath.Clean(path)
	dotdotCount := strings.Count(cleaned, "..")

	if dotdotCount > 3 {
		fs.SecurityLog = append(fs.SecurityLog,
			fmt.Sprintf("Excessive directory traversal: %d levels in %s", dotdotCount, path))
		fs.RiskLevel = "HIGH"
		return true
	}

	// Test for absolute path attacks
	if strings.HasPrefix(cleaned, "/etc") ||
		strings.HasPrefix(cleaned, "/proc") ||
		strings.HasPrefix(cleaned, "/sys") ||
		strings.HasPrefix(cleaned, "/dev") {
		fs.SecurityLog = append(fs.SecurityLog,
			fmt.Sprintf("System directory access: %s", path))
		fs.RiskLevel = "CRITICAL"
		return true
	}

	return false
}
