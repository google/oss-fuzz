package fuzz

import (
	oauth "github.com/google-gemini/gemini-cli-ossfuzz/gofuzz/internal/oauth"
)

// FuzzOAuthTokenRequest fuzzes OAuth token request validation
func FuzzOAuthTokenRequest(data []byte) int {
	_, err := oauth.ValidateTokenRequest(data)
	if err != nil {
		// Validation failures are expected for malformed inputs
		return 0
	}
	return 1
}