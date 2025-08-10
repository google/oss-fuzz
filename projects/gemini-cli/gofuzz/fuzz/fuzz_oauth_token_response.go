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
	oauth "github.com/google-gemini/gemini-cli-ossfuzz/gofuzz/internal/oauth"
)

// FuzzOAuthTokenResponse fuzzes OAuth token response validation
func FuzzOAuthTokenResponse(data []byte) int {
	_, err := oauth.ValidateTokenResponse(data)
	if err != nil {
		// Validation failures are expected for malformed inputs
		return 0
	}
	return 1
}
