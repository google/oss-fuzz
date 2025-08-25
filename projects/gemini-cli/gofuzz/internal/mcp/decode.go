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

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Minimal MCP-like JSON-RPC envelope mirrors for fuzzing purposes.
// Based on public patterns (jsonrpc: "2.0", method, params, id, result, error).

type ID struct {
	Number *float64
	String *string
	Null   bool
}

func (i *ID) UnmarshalJSON(b []byte) error {
	// Accept string, number, or null per JSON-RPC.
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		i.String = &s
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err == nil {
		i.Number = &n
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err == nil {
		if v == nil {
			i.Null = true
			return nil
		}
	}
	return errors.New("invalid id type")
}

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      *ID             `json:"id,omitempty"`
}

type ErrorObject struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ErrorObject    `json:"error,omitempty"`
	ID      *ID             `json:"id,omitempty"`
}

func (r *Request) Validate() error {
	if r.JSONRPC != "" && r.JSONRPC != "2.0" {
		return fmt.Errorf("invalid jsonrpc version: %q", r.JSONRPC)
	}
	if r.Method == "" {
		return errors.New("method required")
	}
	// params may be any JSON type; size checks are enforced by decoder limit outside.
	return nil
}

func (r *Response) Validate() error {
	if r.JSONRPC != "" && r.JSONRPC != "2.0" {
		return fmt.Errorf("invalid jsonrpc version: %q", r.JSONRPC)
	}
	// Either result or error may be present; both present is odd but permit for fuzzing leniency.
	if r.Error != nil && len(r.Error.Message) > 4096 {
		return errors.New("error.message too long")
	}
	return nil
}

// DecodeRequest attempts to decode a Request and validate basic invariants.
func DecodeRequest(data []byte) (*Request, error) {
	dec := json.NewDecoder(bytesLimited(data, 2<<20)) // 2MB cap
	var req Request
	if err := dec.Decode(&req); err != nil {
		return nil, err
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return &req, nil
}

// DecodeResponse attempts to decode a Response and validate basic invariants.
func DecodeResponse(data []byte) (*Response, error) {
	dec := json.NewDecoder(bytesLimited(data, 2<<20)) // 2MB cap
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}
	if err := resp.Validate(); err != nil {
		return nil, err
	}
	return &resp, nil
}

// bytesLimited is a small capped reader to avoid huge allocations.
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
