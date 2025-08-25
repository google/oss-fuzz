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

// FuzzSymlinkValidation directly targets Issue #1121: Symlink path traversal vulnerability
// This vulnerability allows bypassing workspace restrictions using symbolic links
func FuzzSymlinkValidation(data []byte) int {
	if len(data) == 0 || len(data) > 4096 {
		return 0
	}

	input := string(data)
	workspace := "/home/user/workspace"

	// Test various symlink-based path traversal scenarios
	testCases := []struct {
		name string
		path string
	}{
		{"direct_traversal", input},
		{"workspace_relative", filepath.Join(workspace, input)},
		{"symlink_to_sensitive", "/tmp/symlink_to_" + input},
		{"nested_symlink", "/tmp/level1/symlink_to_" + input},
		{"absolute_path", "/" + input},
		{"encoded_path", strings.Replace(input, "/", "%2f", -1)},
		{"null_byte", input + "\x00/etc/passwd"},
	}

	for _, tc := range testCases {
		// Test path validation logic
		if isDangerousSymlinkPath(tc.path) {
			return 1 // Found dangerous path that should be blocked
		}

		// Test canonical path resolution
		clean := filepath.Clean(tc.path)
		if isDangerousAfterClean(clean) {
			return 1 // Path becomes dangerous after cleaning
		}

		// Test workspace boundary validation
		if pathEscapesWorkspace(clean, workspace) {
			return 1 // Path escapes workspace boundaries
		}

		// Test symlink resolution simulation
		if simulatesSymlinkTraversal(clean) {
			return 1 // Path could be used for symlink traversal
		}
	}

	return 0
}

// isDangerousSymlinkPath checks if a path could be used for symlink traversal attacks
func isDangerousSymlinkPath(path string) bool {
	dangerousPatterns := []string{
		"../../../",
		"..\\..\\..\\",
		"/etc/",
		"/root/",
		"/home/",
		"/proc/",
		"/sys/",
		"/var/",
		"/usr/",
		"C:\\Windows\\",
		"C:\\Users\\",
		"~/.ssh/",
		"~/.bashrc",
		".mysql_history",
		"authorized_keys",
		"id_rsa",
		"sudoers",
	}

	pathLower := strings.ToLower(path)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}

	// Check for excessive parent directory traversals
	if strings.Count(path, "..") > 3 {
		return true
	}

	// Check for encoded traversal attempts
	if strings.Contains(path, "%2e%2e%2f") || strings.Contains(path, "..%2f") {
		return true
	}

	return false
}

// isDangerousAfterClean checks if a path becomes dangerous after filepath.Clean
func isDangerousAfterClean(path string) bool {
	// Some paths only reveal their danger after cleaning
	if strings.HasPrefix(path, "/etc/") || strings.HasPrefix(path, "/root/") {
		return true
	}

	// Check for null byte injection
	if strings.Contains(path, "\x00") {
		return true
	}

	return false
}

// pathEscapesWorkspace checks if a path would escape workspace boundaries
func pathEscapesWorkspace(path, workspace string) bool {
	// Resolve the path relative to workspace
	relPath, err := filepath.Rel(workspace, path)
	if err != nil {
		return false // Can't determine relationship
	}

	// If the relative path starts with "..", it escapes the workspace
	if strings.HasPrefix(relPath, "..") {
		return true
	}

	// Check for absolute paths that don't start with workspace
	if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, workspace) {
		return true
	}

	return false
}

// simulatesSymlinkTraversal checks for patterns that could be used with symlinks
func simulatesSymlinkTraversal(path string) bool {
	// These patterns are dangerous when combined with symlinks
	symlinkPatterns := []string{
		"symlink",
		"link",
		"->",
		"/tmp/",
		"/var/tmp/",
		"/dev/shm/",
	}

	pathLower := strings.ToLower(path)
	for _, pattern := range symlinkPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}

	return false
}
