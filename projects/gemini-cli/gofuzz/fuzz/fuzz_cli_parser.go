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

// FuzzCLIParser fuzzes command-line argument parsing logic
func FuzzCLIParser(data []byte) int {
	input := string(data)
	
	// Skip empty or too large inputs
	if len(input) == 0 || len(input) > 8192 {
		return 0
	}
	
	// Parse as space-separated arguments
	args := parseArgs(input)
	
	// Validate parsed arguments
	if validateArgs(args) {
		return 1
	}
	
	return 0
}

// parseArgs simulates CLI argument parsing with shell injection prevention
func parseArgs(input string) []string {
	// Basic argument splitting with quote handling
	var args []string
	var current strings.Builder
	inQuotes := false
	escaped := false
	
	for i, r := range input {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		
		switch r {
		case '\\':
			escaped = true
		case '"', '\'':
			inQuotes = !inQuotes
		case ' ', '\t', '\n':
			if !inQuotes {
				if current.Len() > 0 {
					args = append(args, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(r)
			}
		default:
			current.WriteRune(r)
		}
		
		// Prevent infinite loops on malformed input
		if i > 4096 {
			break
		}
	}
	
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	
	return args
}

// validateArgs checks for dangerous patterns in CLI arguments
func validateArgs(args []string) bool {
	for _, arg := range args {
		// Check for shell injection patterns
		dangerous := []string{
			";", "&&", "||", "|", "`", "$(",
			"<", ">", ">>", "&", "$(", "${",
			"../", "./", "/bin/", "/usr/bin/",
			"rm ", "del ", "format ", "shutdown",
		}
		
		argLower := strings.ToLower(arg)
		for _, pattern := range dangerous {
			if strings.Contains(argLower, pattern) {
				return false // Potentially dangerous
			}
		}
		
		// Check argument length
		if len(arg) > 1024 {
			return false
		}
		
		// Check for control characters
		for _, r := range arg {
			if r < 32 && r != 9 && r != 10 && r != 13 { // Allow tab, LF, CR
				return false
			}
		}
	}
	
	return len(args) > 0 && len(args) <= 100 // Reasonable argument count
}