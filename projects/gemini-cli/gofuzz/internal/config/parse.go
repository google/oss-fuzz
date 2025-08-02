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
	"encoding/json"
	"errors"
	"fmt"
)

// Minimal mirrored shape for Gemini CLI config based on public docs.
// Keep intentionally small and schema-aligned to public behavior only.

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

type RootConfig struct {
	ApiKey     string         `json:"apiKey,omitempty"`
	ProjectID  string         `json:"projectId,omitempty"`
	Theme      *ThemeConfig   `json:"theme,omitempty"`
	Proxy      *ProxyConfig   `json:"proxy,omitempty"`
	Memory     *MemoryConfig  `json:"memory,omitempty"`
	Tooling    *ToolingConfig `json:"tooling,omitempty"`
	// Additional common config fields for better coverage
	LogLevel   string         `json:"logLevel,omitempty"`
	OutputDir  string         `json:"outputDir,omitempty"`
	Timeout    int            `json:"timeout,omitempty"`
	MaxRetries int            `json:"maxRetries,omitempty"`
	Additional map[string]any `json:"-"`
}

// Validate enforces simple invariants derived from public docs.
// This is a mirrored validator; it does NOT read files or perform I/O.
func (c *RootConfig) Validate() error {
	// Example invariants:
	// - apiKey if present must be non-empty (basic check; do not enforce secrets here)
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
	return nil
}

// ParseAndValidate attempts to unmarshal JSON into RootConfig and validate.
func ParseAndValidate(data []byte) (*RootConfig, error) {
	dec := json.NewDecoder(bytesLimited(data, 2<<20)) // 2MB cap
	dec.DisallowUnknownFields()
	var cfg RootConfig
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

// bytesLimited returns a Reader that caps the input size to avoid huge allocations.
func bytesLimited(b []byte, cap int64) *limitedReader {
	if int64(len(b)) > cap {
		b = b[:cap]
	}
	return &limitedReader{b: b}
}

type limitedReader struct {
	b []byte
	i int
}

func (r *limitedReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

var EOF = errors.New("eof")
