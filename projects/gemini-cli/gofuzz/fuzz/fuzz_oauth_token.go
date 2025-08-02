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
	"github.com/google-gemini/gemini-cli-ossfuzz/gofuzz/internal/oauth"
)

func FuzzOAuthTokenResponse(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	token, err := oauth.ValidateTokenResponse(data)
	if err != nil {
		// Error is expected for malformed input
		return 0
	}

	// Validate the parsed token
	if token == nil {
		return 0
	}

	// Additional validation
	if len(token.AccessToken) > 0 {
		return 1
	}

	return 0
}

func FuzzOAuthTokenRequest(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	req, err := oauth.ValidateTokenRequest(data)
	if err != nil {
		// Error is expected for malformed input
		return 0
	}

	// Validate the parsed request
	if req == nil {
		return 0
	}

	// Additional validation
	if len(req.GrantType) > 0 {
		return 1
	}

	return 0
}