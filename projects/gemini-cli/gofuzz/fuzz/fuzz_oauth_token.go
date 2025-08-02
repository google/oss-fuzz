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