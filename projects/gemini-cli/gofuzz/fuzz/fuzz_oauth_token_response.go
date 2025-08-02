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