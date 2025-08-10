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

package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// OAuth token structures for fuzzing token handling logic
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ValidateTokenResponse checks OAuth token response for security issues
func ValidateTokenResponse(data []byte) (*TokenResponse, error) {
	if len(data) > 64*1024 { // 64KB limit
		return nil, errors.New("token response too large")
	}

	var token TokenResponse
	if err := json.NewDecoder(bytesLimited(data, 1<<20)).Decode(&token); err != nil {
		return nil, fmt.Errorf("invalid token JSON: %w", err)
	}

	// Validate access token
	if err := validateToken(token.AccessToken, "access_token"); err != nil {
		return nil, err
	}

	// Validate token type
	if token.TokenType != "" {
		validTypes := []string{"Bearer", "bearer", "MAC", "mac"}
		valid := false
		for _, t := range validTypes {
			if token.TokenType == t {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid token_type: %s", token.TokenType)
		}
	}

	// Validate expires_in
	if token.ExpiresIn < 0 || token.ExpiresIn > 86400*365 { // Max 1 year
		return nil, errors.New("invalid expires_in value")
	}

	// Validate refresh token if present
	if token.RefreshToken != "" {
		if err := validateToken(token.RefreshToken, "refresh_token"); err != nil {
			return nil, err
		}
	}

	// Validate ID token if present (basic JWT structure check)
	if token.IDToken != "" {
		if err := validateJWTStructure(token.IDToken); err != nil {
			return nil, fmt.Errorf("invalid id_token: %w", err)
		}
	}

	return &token, nil
}

// ValidateTokenRequest checks OAuth token request for security issues
func ValidateTokenRequest(data []byte) (*TokenRequest, error) {
	if len(data) > 32*1024 { // 32KB limit
		return nil, errors.New("token request too large")
	}

	var req TokenRequest
	if err := json.NewDecoder(bytesLimited(data, 1<<20)).Decode(&req); err != nil {
		return nil, fmt.Errorf("invalid request JSON: %w", err)
	}

	// Validate grant type
	validGrants := []string{
		"authorization_code",
		"refresh_token",
		"client_credentials",
		"password", // Though not recommended
	}
	valid := false
	for _, g := range validGrants {
		if req.GrantType == g {
			valid = true
			break
		}
	}
	if !valid {
		return nil, fmt.Errorf("invalid grant_type: %s", req.GrantType)
	}

	// Validate redirect URI format
	if req.RedirectURI != "" {
		if err := validateRedirectURI(req.RedirectURI); err != nil {
			return nil, err
		}
	}

	// Check for potential injection in client credentials
	if strings.ContainsAny(req.ClientID, "<>\"'&;") {
		return nil, errors.New("potentially dangerous characters in client_id")
	}

	return &req, nil
}

func validateToken(token, tokenType string) error {
	if len(token) == 0 {
		return fmt.Errorf("%s cannot be empty", tokenType)
	}

	if len(token) > 8192 { // 8KB max token size
		return fmt.Errorf("%s too long", tokenType)
	}

	// Check for obvious injection attempts
	dangerous := []string{"<script", "javascript:", "data:", "vbscript:", "onload="}
	tokenLower := strings.ToLower(token)
	for _, pattern := range dangerous {
		if strings.Contains(tokenLower, pattern) {
			return fmt.Errorf("potentially dangerous pattern in %s", tokenType)
		}
	}

	return nil
}

func validateJWTStructure(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("JWT must have 3 parts separated by dots")
	}

	// Basic length checks for each part
	for i, part := range parts {
		if len(part) == 0 {
			return fmt.Errorf("JWT part %d cannot be empty", i+1)
		}
		if len(part) > 16384 { // 16KB per part max
			return fmt.Errorf("JWT part %d too long", i+1)
		}
	}

	return nil
}

func validateRedirectURI(uri string) error {
	if len(uri) > 2048 {
		return errors.New("redirect_uri too long")
	}

	// Must be HTTPS or localhost for security
	if !strings.HasPrefix(uri, "https://") &&
		!strings.HasPrefix(uri, "http://localhost") &&
		!strings.HasPrefix(uri, "http://127.0.0.1") {
		return errors.New("redirect_uri must use HTTPS or localhost")
	}

	// Check for dangerous characters
	if strings.ContainsAny(uri, "<>\"'") {
		return errors.New("redirect_uri contains dangerous characters")
	}

	return nil
}

// bytesLimited returns an io.Reader capped to at most cap bytes and ends with io.EOF.
func bytesLimited(b []byte, cap int64) io.Reader {
	if int64(len(b)) > cap {
		b = b[:cap]
	}
	return bytes.NewReader(b)
}
