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
	"strings"
)

// FuzzShellValidation tests shell command validation and allowlist bypasses
// Critical for preventing command injection in tools like run_shell_command
func FuzzShellValidation(data []byte) int {
	if len(data) == 0 || len(data) > 2048 {
		return 0
	}

	command := string(data)

	// Test various command injection scenarios
	testCases := []string{
		command,
		"echo " + command,
		command + "; ls",
		command + " && cat /etc/passwd",
		command + " | cat /etc/passwd",
		command + " `cat /etc/passwd`",
		command + " $(cat /etc/passwd)",
		"bash -c " + command,
		"sh -c " + command,
	}

	for _, testCmd := range testCases {
		// Test command validation
		if containsShellMetacharacters(testCmd) {
			return 1 // Found dangerous shell metacharacters
		}

		// Test for command injection patterns
		if containsInjectionPatterns(testCmd) {
			return 1 // Found injection attempt
		}

		// Test allowlist bypass attempts
		if bypassesAllowlist(testCmd) {
			return 1 // Found allowlist bypass attempt
		}

		// Test for encoded command injection
		if containsEncodedInjection(testCmd) {
			return 1 // Found encoded injection attempt
		}
	}

	return 0
}

// containsShellMetacharacters checks for dangerous shell metacharacters
func containsShellMetacharacters(cmd string) bool {
	dangerousChars := []string{
		";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r",
		"\\", "\"", "'", "*", "?", "[", "]", "{", "}", "~", "#",
	}

	for _, char := range dangerousChars {
		if strings.Contains(cmd, char) {
			return true
		}
	}

	return false
}

// containsInjectionPatterns checks for common command injection patterns
func containsInjectionPatterns(cmd string) bool {
	injectionPatterns := []string{
		"cat /etc/passwd",
		"cat /etc/shadow",
		"rm -rf",
		"curl ",
		"wget ",
		"nc -e",
		"netcat",
		"bash -i",
		"sh -i",
		"python -c",
		"perl -e",
		"php -r",
		"node -e",
		"eval(",
		"exec(",
		"system(",
		"popen(",
	}

	cmdLower := strings.ToLower(cmd)
	for _, pattern := range injectionPatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}

	return false
}

// bypassesAllowlist checks for attempts to bypass command allowlists
func bypassesAllowlist(cmd string) bool {
	// Common allowlist bypass techniques
	bypassPatterns := []string{
		"bash",
		"sh",
		"dash",
		"env ",
		"exec ",
		"eval ",
		"system ",
		"popen ",
		"/bin/",
		"/usr/bin/",
		"/usr/local/bin/",
		"which ",
		"whereis ",
		"command ",
		"type ",
		"hash ",
	}

	cmdLower := strings.ToLower(cmd)
	for _, pattern := range bypassPatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}

	return false
}

// containsEncodedInjection checks for encoded/escaped injection attempts
func containsEncodedInjection(cmd string) bool {
	// URL encoding patterns
	if strings.Contains(cmd, "%20") || strings.Contains(cmd, "%2f") {
		return true
	}

	// Hex encoding patterns
	if strings.Contains(cmd, "\\x20") || strings.Contains(cmd, "\\x2f") {
		return true
	}

	// Octal encoding patterns
	if strings.Contains(cmd, "\\040") || strings.Contains(cmd, "\\057") {
		return true
	}

	// Unicode encoding patterns
	if strings.Contains(cmd, "\\u0020") || strings.Contains(cmd, "\\u002f") {
		return true
	}

	return false
}
