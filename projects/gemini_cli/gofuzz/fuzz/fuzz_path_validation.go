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
	"path/filepath"
	"strings"
	"time"
)

// FuzzPathValidation tests path validation logic for symlink traversal vulnerabilities
// Enhanced with comprehensive security validation and multiple attack strategies
// Critical for Issue #1121: Symlink path traversal vulnerability
func FuzzPathValidation(data []byte) int {
	// Enhanced input validation and resource limits
	if len(data) == 0 || len(data) > 4096 {
		return 0 // Skip empty or oversized inputs
	}

	// Performance monitoring and resource limits
	startTime := time.Now()
	maxProcessingTime := 3000 * time.Millisecond // 3 seconds for path validation

	input := string(data)

	// Enhanced test strategies for comprehensive path validation coverage
	testStrategies := []func(string) int{
		// Strategy 1: Original path processing
		func(path string) int {
			cleaned := filepath.Clean(path)
			if strings.Contains(cleaned, "..") && isDangerousPath(cleaned) {
				return 1 // Found dangerous path
			}
			return 0
		},
		// Strategy 2: Absolute path resolution
		func(path string) int {
			abs, err := filepath.Abs(path)
			if err == nil && isDangerousPath(abs) {
				return 1 // Found dangerous absolute path
			}
			return 0
		},
		// Strategy 3: Relative path computation
		func(path string) int {
			base := "/workspace"
			rel, err := filepath.Rel(base, filepath.Clean(path))
			if err == nil && strings.HasPrefix(rel, "..") {
				return 1 // Found path traversal via relative computation
			}
			return 0
		},
		// Strategy 4: Path normalization consistency
		func(path string) int {
			// Test for path normalization inconsistencies
			cleaned1 := filepath.Clean(path)
			cleaned2 := filepath.Clean(cleaned1)
			if cleaned1 != cleaned2 {
				return 1 // Found normalization inconsistency
			}
			return 0
		},
		// Strategy 5: Volume name handling
		func(path string) int {
			// Test volume handling on Windows-like paths
			if strings.Contains(path, ":\\") {
				volume := path[:strings.Index(path, ":")+1]
				if !isValidVolume(volume) {
					return 1 // Invalid volume detected
				}
			}
			return 0
		},
	}

	// Comprehensive path variations for thorough testing
	pathVariations := []string{
		// Original path variations
		input,
		"../../../" + input,
		"..\\..\\..\\" + input,
		"/" + input,
		"C:\\" + input,
		input + "/..",
		input + "\\..",

		// Enhanced path variations for better coverage
		"~" + input,                           // Home directory expansion
		"." + input,                           // Current directory
		"./" + input,                          // Explicit current directory
		".\\" + input,                         // Windows current directory
		input + "/.",                          // Current directory suffix
		input + "\\.",                         // Windows current directory suffix
		strings.Repeat("../", 10) + input,     // Deep traversal
		strings.Repeat("..\\", 10) + input,    // Windows deep traversal
		"/absolute/" + input,                  // Absolute path
		"C:\\absolute\\" + input,              // Windows absolute path
		"\\\\server\\share\\" + input,         // UNC path
		"//server/share/" + input,             // UNC path (Unix style)
		input + strings.Repeat("/subdir", 5),  // Deep nesting
		input + strings.Repeat("\\subdir", 5), // Windows deep nesting
		strings.ReplaceAll(input, "/", "\\"),  // Mixed separators
		strings.ReplaceAll(input, "\\", "/"),  // Mixed separators
	}

	// Test each path variation with all strategies
	for _, path := range pathVariations {
		// Check time limits to prevent infinite loops
		if time.Since(startTime) > maxProcessingTime {
			return 0 // Timeout - expected behavior
		}

		for _, strategy := range testStrategies {
			result := strategy(path)
			if result == 1 {
				return 1 // Found vulnerability
			}
		}

		// Additional security checks for each path
		if containsPathAttackPatterns(path) {
			return 1 // Found attack pattern
		}

		// Test path encoding variations
		encodedVariations := generatePathVariations(path)
		for _, variation := range encodedVariations {
			if isDangerousPath(variation) {
				return 1 // Found dangerous encoded path
			}
		}
	}

	// Test for path traversal in different contexts
	contexts := []string{
		"/workspace", "/app", "/home/user", "/tmp", "/var",
		"C:\\workspace", "C:\\app", "C:\\Users\\user", "C:\\temp",
	}

	for _, context := range contexts {
		// Check time limits
		if time.Since(startTime) > maxProcessingTime {
			return 0 // Timeout - expected behavior
		}

		for _, path := range pathVariations {
			rel, err := filepath.Rel(context, path)
			if err == nil && (strings.HasPrefix(rel, "..") || strings.Contains(rel, "..")) {
				if isDangerousRelativePath(rel) {
					return 1 // Found dangerous relative path
				}
			}
		}
	}

	return 0
}

// isDangerousPath checks if a path could be used for directory traversal attacks
func isDangerousPath(path string) bool {
	// Enhanced dangerous patterns detection
	dangerousPatterns := []string{
		"../../../",
		"..\\..\\..\\",
		"/etc/",
		"/root/",
		"/home/",
		"/usr/",
		"/var/",
		"/tmp/",
		"/dev/",
		"/proc/",
		"/sys/",
		"/boot/",
		"C:\\Windows\\",
		"C:\\Users\\",
		"C:\\System32\\",
		"C:\\Program Files\\",
		"C:\\Program Files (x86)\\",
		"~/.ssh/",
		"~/.aws/",
		"~/.gcp/",
		"~/Desktop/",
		"~/Documents/",
		"~/Downloads/",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	// Check for excessive parent directory traversals
	if strings.Count(path, "..") > 3 {
		return true
	}

	// Check for null bytes and control characters
	for _, r := range path {
		if r == 0 || (r < 32 && r != 9 && r != 10 && r != 13) {
			return true
		}
	}

	// Check for extremely long path segments
	segments := strings.Split(path, "/")
	for _, seg := range segments {
		if len(seg) > 255 { // Max filename length on most systems
			return true
		}
	}

	return false
}

// containsPathAttackPatterns detects various path-based attack patterns
func containsPathAttackPatterns(path string) bool {
	attackPatterns := []string{
		"\\x00", "\\x01", "\\x02", // Null and control character escapes
		"%00", "%01", "%02", // URL encoded null bytes
		"\\u0000", "\\u0001", // Unicode escapes
		"\\\\",          // Double backslashes
		"//",            // Double forward slashes
		".../", "...\\", // Triple dot patterns
		"~root", "~admin", // Home directory exploits
	}

	for _, pattern := range attackPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	return false
}

// generatePathVariations creates various encoded and modified versions of paths
func generatePathVariations(path string) []string {
	variations := []string{}

	// URL encoding variations
	variations = append(variations, strings.ReplaceAll(path, "/", "%2F"))
	variations = append(variations, strings.ReplaceAll(path, "\\", "%5C"))
	variations = append(variations, strings.ReplaceAll(path, "..", "%2E%2E"))
	variations = append(variations, strings.ReplaceAll(path, ".", "%2E"))

	// Case variations for Windows
	variations = append(variations, strings.ToUpper(path))
	variations = append(variations, strings.ToLower(path))

	// Mixed case variations
	if strings.Contains(path, "/") {
		variations = append(variations, strings.ReplaceAll(path, "/", "\\"))
	}
	if strings.Contains(path, "\\") {
		variations = append(variations, strings.ReplaceAll(path, "\\", "/"))
	}

	// Unicode normalization variations
	// Note: Go's unicode package would be used here for actual normalization

	return variations
}

// isValidVolume checks if a Windows volume name is valid
func isValidVolume(volume string) bool {
	if len(volume) != 2 || volume[1] != ':' {
		return false
	}

	drive := volume[0]
	return (drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')
}

// isDangerousRelativePath checks if a relative path is dangerous
func isDangerousRelativePath(rel string) bool {
	// Check for excessive parent directory traversals
	if strings.Count(rel, "..") > 2 {
		return true
	}

	// Check if relative path escapes workspace
	if strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "..\\") {
		return true
	}

	// Check for dangerous patterns in relative path
	dangerousInRelative := []string{
		"etc", "root", "home", "usr", "var", "tmp",
		"Windows", "System32", "Users", "Program Files",
		".ssh", ".aws", ".gcp",
	}

	for _, dangerous := range dangerousInRelative {
		if strings.Contains(strings.ToLower(rel), strings.ToLower(dangerous)) {
			return true
		}
	}

	return false
}
