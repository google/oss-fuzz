package fuzz

import (
	cfg "github.com/google-gemini/gemini-cli-ossfuzz/gofuzz/internal/config"
)

// FuzzConfigParser is the libFuzzer entrypoint for config parsing/validation.
func FuzzConfigParser(data []byte) int {
	_, err := cfg.ParseAndValidate(data)
	if err != nil {
		// Validation failures are expected for malformed inputs.
		return 0
	}
	return 1
}
