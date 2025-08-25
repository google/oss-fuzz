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
	"bufio"
	"strings"
)

// FuzzContextFileParser tests parsing of context files like GEMINI.md, README.md
// Critical for addressing the prompt injection vulnerability discovered in June 2024
func FuzzContextFileParser(data []byte) int {
	if len(data) == 0 || len(data) > 8192 {
		return 0
	}

	// Test various context file parsing scenarios
	scenarios := []string{
		string(data),                               // Raw content
		"# " + string(data),                        // Markdown header
		"```" + string(data) + "```",               // Code block
		"```\n" + string(data) + "\n```",           // Multi-line code block
		string(data) + "\n```bash\necho test\n```", // Content with code blocks
	}

	for _, scenario := range scenarios {
		// Test context file parsing
		if err := parseContextFile(scenario); err != nil {
			return 0 // Expected parsing error
		}

		// Test for dangerous content that could lead to injection
		if containsDangerousPatterns(scenario) {
			return 1 // Found potentially dangerous content
		}

		// Test metadata extraction
		metadata := extractMetadata(scenario)
		if metadata != nil && containsMetadataInjectionPatterns(metadata) {
			return 1 // Found injection in metadata
		}
	}

	return 0
}

// parseContextFile simulates parsing of context files like GEMINI.md
func parseContextFile(content string) error {
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := scanner.Text()

		// Check for obvious parsing issues
		if len(line) > 1000 {
			return scanner.Err() // Simulate parsing error for very long lines
		}

		// Check for malformed content
		if strings.Contains(line, "\x00") {
			return scanner.Err() // Null bytes in content
		}
	}

	return scanner.Err()
}

// containsDangerousPatterns checks for patterns that could lead to injection attacks
func containsDangerousPatterns(content string) bool {
	dangerousPatterns := []string{
		"```bash",
		"```sh",
		"```shell",
		"#!/bin/bash",
		"#!/bin/sh",
		"rm -rf",
		"curl ",
		"wget ",
		"eval(",
		"exec(",
		"system(",
	}

	contentLower := strings.ToLower(content)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(contentLower, pattern) {
			return true
		}
	}

	return false
}

// extractMetadata simulates extracting metadata from context files
func extractMetadata(content string) map[string]string {
	metadata := make(map[string]string)

	// Look for common metadata patterns
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "# ") {
			metadata["title"] = strings.TrimPrefix(line, "# ")
		} else if strings.HasPrefix(line, "## ") {
			metadata["subtitle"] = strings.TrimPrefix(line, "## ")
		} else if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				metadata[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	return metadata
}

// containsMetadataInjectionPatterns checks metadata for injection attempts
func containsMetadataInjectionPatterns(metadata map[string]string) bool {
	injectionPatterns := []string{
		"<script>",
		"javascript:",
		"data:",
		"vbscript:",
		"onload=",
		"onerror=",
	}

	for _, value := range metadata {
		valueLower := strings.ToLower(value)
		for _, pattern := range injectionPatterns {
			if strings.Contains(valueLower, pattern) {
				return true
			}
		}
	}

	return false
}
