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

	cli "github.com/google-gemini/gemini-cli-ossfuzz/gofuzz/internal/cli"
)

// FuzzCLIParser routes fuzz data into the mirrored CLI argument parser.
// It accepts NUL (\x00) delimited argv to maximize permutations and coverage.
func FuzzCLIParser(data []byte) int {
	if len(data) == 0 || len(data) > 8192 {
		return 0
	}

	// Interpret input as NUL-delimited argv. Trim trailing NULs.
	raw := strings.TrimRight(string(data), "\x00\n\r\t ")
	if len(raw) == 0 {
		return 0
	}
	argv := strings.Split(raw, "\x00")

	// Fallback: if there is only one token, split on whitespace to avoid trivial cases.
	if len(argv) == 1 {
		argv = strings.Fields(raw)
	}
	if len(argv) == 0 {
		return 0
	}

	if _, err := cli.ParseArgs(argv); err == nil {
		return 1
	}
	return 0
}
