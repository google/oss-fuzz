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
// limitations under the License.package fuzz

import "strings"

// FuzzCLIParser fuzzes command-line argument parsing logic.
func FuzzCLIParser(data []byte) int {
	// Skip empty or huge inputs (keep runs fast/deterministic).
	if len(data) == 0 || len(data) > 1<<20 { // 1 MiB cap
		return 0
	}
	args := parseArgs(string(data))

	// Structural signal only: parsed some bounded argv → interesting.
	if len(args) > 0 && len(args) <= 100 {
		return 1
	}
	return 0
}

// parseArgs simulates CLI-style tokenization with quotes/escapes.
func parseArgs(input string) []string {
	var args []string
	var current strings.Builder
	inQuotes := false
	escape := false
	quoteChar := rune(0)

	for _, r := range input {
		if escape {
			current.WriteRune(r)
			escape = false
			continue
		}
		if r == '\\' {
			escape = true
			continue
		}
		if inQuotes {
			if r == quoteChar {
				inQuotes = false
			} else {
				current.WriteRune(r)
			}
			continue
		}
		if r == '"' || r == '\'' {
			inQuotes = true
			quoteChar = r
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(r)
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}
