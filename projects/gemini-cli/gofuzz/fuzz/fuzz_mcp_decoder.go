package fuzz

import (
	mcp "github.com/google-gemini/gemini-cli-ossfuzz/gofuzz/internal/mcp"
)

// FuzzMCPDecoder fuzzes MCP-style JSON-RPC envelopes (request/response).
func FuzzMCPDecoder(data []byte) int {
	// Try request decode/validate
	if _, err := mcp.DecodeRequest(data); err == nil {
		return 1
	}
	// Try response decode/validate
	if _, err := mcp.DecodeResponse(data); err == nil {
		return 1
	}
	return 0
}
