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
	mcp "github.com/google-gemini/gemini-cli-ossfuzz/gofuzz/internal/mcp"
)

// FuzzMCPRequest focuses corpus on MCP Request envelopes.
func FuzzMCPRequest(data []byte) int {
	if len(data) == 0 || len(data) > 1<<20 { // 1MB upper bound
		return 0
	}
	if _, err := mcp.DecodeRequest(data); err == nil {
		return 1
	}
	return 0
}

// FuzzMCPResponse focuses corpus on MCP Response envelopes.
func FuzzMCPResponse(data []byte) int {
	if len(data) == 0 || len(data) > 1<<20 {
		return 0
	}
	if _, err := mcp.DecodeResponse(data); err == nil {
		return 1
	}
	return 0
}
