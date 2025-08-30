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

//go:build gofuzz
// +build gofuzz

package fuzz

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzSymlinkValidation targets Issue #1121 - Critical symlink traversal vulnerability
// This fuzzer specifically tests for symlink-based path traversal attacks
func FuzzSymlinkValidation(data []byte) int {
	// Parse input as JSON for structured fuzzing
	var input struct {
		Path      string `json:"path"`
		Workspace string `json:"workspace"`
		Symlink   string `json:"symlink"`
		Target    string `json:"target"`
	}
	
	if err := json.Unmarshal(data, &input); err != nil {
		// Try raw path traversal if not valid JSON
		return fuzzRawSymlinkPath(string(data))
	}
	// Test symlink resolution with workspace boundaries
	if input.Workspace == "" {
		input.Workspace = "/workspace"
	}
	
	// Critical vulnerability patterns from Issue #1121
	vulnerablePatterns := []string{
		"../../../etc/passwd",
		"../../.ssh/id_rsa",
		"../../../root/.bashrc",
		filepath.Join("..", "..", "..", "etc", "shadow"),
		"workspace/../../../sensitive",
		"/tmp/symlink/../../../etc/hosts",
	}
	
	// Test if input path matches vulnerable patterns
	for _, pattern := range vulnerablePatterns {
		if strings.Contains(input.Path, pattern) || strings.Contains(input.Symlink, pattern) {
			// Simulate vulnerability detection
			validateSymlinkSecurity(input.Path, input.Workspace, input.Symlink)
		}
	}
	
	// Test canonical path resolution
	if input.Path != "" {
		// Clean the path
		cleanPath := filepath.Clean(input.Path)
		absPath := filepath.Join(input.Workspace, cleanPath)
		
		// Check if path escapes workspace
		if !strings.HasPrefix(absPath, input.Workspace) {
			// Path traversal detected - this is the vulnerability!			return 1 // Interesting input found
		}
		
		// Test symlink target validation
		if input.Target != "" {
			targetPath := filepath.Join(input.Workspace, input.Target)
			if !strings.HasPrefix(targetPath, input.Workspace) {
				return 1 // Symlink target escapes workspace
			}
		}
	}
	
	// Test double symlink chain attack
	if input.Symlink != "" && input.Target != "" {
		chain := []string{input.Path, input.Symlink, input.Target}
		for _, link := range chain {
			if isPathTraversal(link, input.Workspace) {
				return 1
			}
		}
	}
	
	return 0
}

// fuzzRawSymlinkPath tests raw path input
func fuzzRawSymlinkPath(path string) int {
	workspace := "/workspace"
	
	// Direct path traversal test
	if strings.Contains(path, "../") || strings.Contains(path, "..\\") {
		cleanPath := filepath.Clean(path)		absPath := filepath.Join(workspace, cleanPath)
		
		if !strings.HasPrefix(absPath, workspace) {
			return 1 // Vulnerability detected
		}
	}
	
	// Test null byte injection
	if strings.Contains(path, "\x00") {
		return 1 // Null byte attack detected
	}
	
	// Test Unicode normalization attacks
	if containsUnicodeTraversal(path) {
		return 1
	}
	
	return 0
}

// validateSymlinkSecurity simulates the vulnerable validation logic
func validateSymlinkSecurity(path, workspace, symlink string) bool {
	// This simulates the VULNERABLE behavior from Issue #1121
	// The bug: Checking user-provided path instead of canonical path
	
	// VULNERABLE CODE (what NOT to do):
	// if strings.HasPrefix(path, workspace) { return true }
	
	// CORRECT CODE (what should be done):
	canonicalPath := filepath.Clean(filepath.Join(workspace, path))
	return strings.HasPrefix(canonicalPath, workspace)
}
// isPathTraversal checks if a path attempts to escape the workspace
func isPathTraversal(path, workspace string) bool {
	// Multiple validation approaches to catch edge cases
	
	// 1. Clean and check
	cleanPath := filepath.Clean(path)
	if strings.HasPrefix(cleanPath, "..") {
		return true
	}
	
	// 2. Absolute path check
	absPath := filepath.Join(workspace, cleanPath)
	if !strings.HasPrefix(absPath, workspace) {
		return true
	}
	
	// 3. Check for special sequences
	dangerousPatterns := []string{
		"..%2f", "..%5c", // URL encoded traversal
		"..%252f", "..%255c", // Double encoded
		"..;", "..", // Path parameter pollution
		"..%00", // Null byte injection
	}
	
	lowerPath := strings.ToLower(path)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	
	return false
}
// containsUnicodeTraversal checks for Unicode-based traversal attacks
func containsUnicodeTraversal(path string) bool {
	// Unicode variations of directory traversal
	unicodeVariations := []string{
		"\u002e\u002e\u002f", // ../
		"\u002e\u002e\u005c", // ..\
		"\uff0e\uff0e\u002f", // Fullwidth ../
		"\u2025\u2025\u002f", // Double dot leader
	}
	
	for _, variant := range unicodeVariations {
		if strings.Contains(path, variant) {
			return true
		}
	}
	
	return false
}

// Fuzz entry point for go-fuzz compatibility
func Fuzz(data []byte) int {
	return FuzzSymlinkValidation(data)
}