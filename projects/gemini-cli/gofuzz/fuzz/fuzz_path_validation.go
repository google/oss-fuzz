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
)

// FuzzPathValidation tests path validation logic for symlink traversal vulnerabilities
// Critical for Issue #1121: Symlink path traversal vulnerability
func FuzzPathValidation(data []byte) int {
	if len(data) == 0 || len(data) > 4096 {
		return 0
	}

	input := string(data)

	// Test various path traversal scenarios
	paths := []string{
		input,
		"../../../" + input,
		"..\\..\\..\\" + input,
		"/" + input,
		"C:\\" + input,
		input + "/..",
		input + "\\..",
	}

	for _, path := range paths {
		// Test filepath.Clean - should resolve ../ sequences
		cleaned := filepath.Clean(path)

		// Test for dangerous patterns after cleaning
		if strings.Contains(cleaned, "..") {
			// Check if this could escape workspace boundaries
			if isDangerousPath(cleaned) {
				return 1 // Found potentially dangerous path
			}
		}

		// Test filepath.Abs - should resolve relative paths
		abs, err := filepath.Abs(path)
		if err == nil && isDangerousPath(abs) {
			return 1 // Found dangerous absolute path
		}

		// Test filepath.Rel - should compute relative paths safely
		base := "/workspace"
		rel, err := filepath.Rel(base, cleaned)
		if err == nil && strings.HasPrefix(rel, "..") {
			return 1 // Found path traversal via relative computation
		}
	}

	return 0
}

// isDangerousPath checks if a path could be used for directory traversal attacks
func isDangerousPath(path string) bool {
	// Check for obvious traversal patterns
	dangerousPatterns := []string{
		"../../../",
		"..\\..\\..\\",
		"/etc/",
		"/root/",
		"/home/",
		"C:\\Windows\\",
		"C:\\Users\\",
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

	return false
}
