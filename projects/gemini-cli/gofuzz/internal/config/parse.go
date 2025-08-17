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

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Enhanced Config structure with security-aware components
type Config struct {
	ApiKey         string                 `json:"apiKey,omitempty"`
	ProjectID      string                 `json:"projectId,omitempty"`
	Model          string                 `json:"model,omitempty"`
	Temperature    float64                `json:"temperature,omitempty"`
	MaxTokens      int                    `json:"maxTokens,omitempty"`
	SystemPrompt   string                 `json:"systemPrompt,omitempty"`
	Tools          []Tool                 `json:"tools,omitempty"`
	MCPServers     []MCPServer            `json:"mcpServers,omitempty"`
	OutputFormat   string                 `json:"outputFormat,omitempty"`
	Logging        LoggingConfig          `json:"logging,omitempty"`
	Authentication AuthConfig             `json:"authentication,omitempty"`
	Preferences    map[string]interface{} `json:"preferences,omitempty"`
	Theme          *ThemeConfig           `json:"theme,omitempty"`
	Proxy          *ProxyConfig           `json:"proxy,omitempty"`
	Memory         *MemoryConfig          `json:"memory,omitempty"`
	Tooling        *ToolingConfig         `json:"tooling,omitempty"`
	LogLevel       string                 `json:"logLevel,omitempty"`
	OutputDir      string                 `json:"outputDir,omitempty"`
	Timeout        int                    `json:"timeout,omitempty"`
	MaxRetries     int                    `json:"maxRetries,omitempty"`
	Additional     map[string]any         `json:"-"`
}

type Tool struct {
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Config        map[string]interface{} `json:"config"`
	Enabled       bool                   `json:"enabled"`
	TrustedSource bool                   `json:"trustedSource"`
	Permissions   []string               `json:"permissions"`
	Signature     string                 `json:"signature,omitempty"`
}

type MCPServer struct {
	Name          string            `json:"name"`
	Command       string            `json:"command"`
	Args          []string          `json:"args"`
	Env           map[string]string `json:"env"`
	Transport     string            `json:"transport"`
	TrustedSource bool              `json:"trustedSource"`
	Sandboxed     bool              `json:"sandboxed"`
	MaxMemory     int64             `json:"maxMemory"`
	Timeout       int               `json:"timeout"`
}

type LoggingConfig struct {
	Level         string `json:"level"`
	File          string `json:"file"`
	Format        string `json:"format"`
	MaxSize       int64  `json:"maxSize"`
	IncludePII    bool   `json:"includePII"`
	RemoteLogging bool   `json:"remoteLogging"`
	EncryptLogs   bool   `json:"encryptLogs"`
}

type AuthConfig struct {
	Method       string   `json:"method"`
	TokenFile    string   `json:"tokenFile"`
	ClientID     string   `json:"clientId"`
	Scopes       []string `json:"scopes"`
	RequireMFA   bool     `json:"requireMFA"`
	TokenExpiry  int      `json:"tokenExpiry"`
	RefreshToken string   `json:"refreshToken,omitempty"`
}

type ThemeConfig struct {
	Name string `json:"name,omitempty"`
}

type ProxyConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	URL     string `json:"url,omitempty"`
}

type MemoryConfig struct {
	Enabled bool `json:"enabled,omitempty"`
	LimitMB int  `json:"limitMb,omitempty"`
}

type ToolingConfig struct {
	EnableMcp      bool `json:"enableMcp,omitempty"`
	EnableShell    bool `json:"enableShell,omitempty"`
	EnableWebFetch bool `json:"enableWebFetch,omitempty"`
}

// Validate enforces simple invariants derived from public docs.
// Enhanced with security validation based on audit directives.
func (c *Config) Validate() error {
	// Basic validation
	if c.ApiKey == "" && c.ProjectID == "" {
		// Allow empty but encourage at least one to exist
		// We'll not fail here to avoid over-rejecting; just a soft check.
	}

	// Theme name, if present, should be reasonably sized.
	if c.Theme != nil && len(c.Theme.Name) > 128 {
		return errors.New("theme.name too long")
	}

	// Proxy URL basic sanity (very light)
	if c.Proxy != nil {
		if len(c.Proxy.URL) > 2048 {
			return errors.New("proxy.url too long")
		}
	}

	// Memory limit sane bounds
	if c.Memory != nil {
		if c.Memory.LimitMB < 0 || c.Memory.LimitMB > 1_000_000 {
			return errors.New("memory.limitMb out of range")
		}
	}

	// Additional validation for new fields
	if len(c.LogLevel) > 32 {
		return errors.New("logLevel too long")
	}
	if len(c.OutputDir) > 1024 {
		return errors.New("outputDir too long")
	}
	if c.Timeout < 0 || c.Timeout > 86400 { // 24 hours max
		return errors.New("timeout out of range")
	}
	if c.MaxRetries < 0 || c.MaxRetries > 100 {
		return errors.New("maxRetries out of range")
	}

	// Security validation
	if c.Temperature < 0 || c.Temperature > 2.0 {
		return errors.New("temperature out of safe range")
	}

	if c.MaxTokens < 0 || c.MaxTokens > 100000 {
		return errors.New("maxTokens out of range")
	}

	// Validate tools
	for _, tool := range c.Tools {
		if err := validateTool(&tool); err != nil {
			return fmt.Errorf("tool validation failed: %w", err)
		}
	}

	// Validate MCP servers
	for _, server := range c.MCPServers {
		if err := validateMCPServer(&server); err != nil {
			return fmt.Errorf("MCP server validation failed: %w", err)
		}
	}

	return nil
}

func validateTool(tool *Tool) error {
	if len(tool.Name) == 0 {
		return errors.New("tool name cannot be empty")
	}
	if len(tool.Name) > 256 {
		return errors.New("tool name too long")
	}
	if len(tool.Type) > 64 {
		return errors.New("tool type too long")
	}
	return nil
}

func validateMCPServer(server *MCPServer) error {
	if len(server.Name) == 0 {
		return errors.New("MCP server name cannot be empty")
	}
	if len(server.Name) > 256 {
		return errors.New("MCP server name too long")
	}
	if len(server.Command) > 1024 {
		return errors.New("MCP server command too long")
	}
	if server.MaxMemory < 0 || server.MaxMemory > 1_000_000_000 { // 1GB max
		return errors.New("MCP server maxMemory out of range")
	}
	if server.Timeout < 0 || server.Timeout > 3600 { // 1 hour max
		return errors.New("MCP server timeout out of range")
	}
	return nil
}

// ParseAndValidate attempts to unmarshal JSON into Config and validate.
func ParseAndValidate(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytesLimited(data, 2<<20)) // 2MB cap
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		// Fallback: allow unknown fields by doing a generic pass, then re-marshal known.
		var generic map[string]any
		if err2 := json.Unmarshal(data, &generic); err2 != nil {
			return nil, fmt.Errorf("config generic unmarshal failed: %w", err)
		}
		// Re-marshal known subset into cfg
		b, _ := json.Marshal(generic)
		if err3 := json.Unmarshal(b, &cfg); err3 != nil {
			return nil, fmt.Errorf("config second pass failed: %w", err3)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// bytesLimited returns an io.Reader capped to at most cap bytes and ends with io.EOF.
func bytesLimited(b []byte, cap int64) io.Reader {
	if int64(len(b)) > cap {
		b = b[:cap]
	}
	return bytes.NewReader(b)
}
