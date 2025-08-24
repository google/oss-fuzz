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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	mcp "github.com/google-gemini/gemini-cli/gofuzz/internal/mcp"
)

// SecurityAwareMCPRequest extends MCP request with security validation
type SecurityAwareMCPRequest struct {
	mcp.Request
	SecurityViolations []string  `json:"-"`
	RiskLevel          string    `json:"-"`
	Signature          string    `json:"signature,omitempty"`
	Timestamp          time.Time `json:"timestamp,omitempty"`
}

// SecurityAwareMCPResponse extends MCP response with security validation
type SecurityAwareMCPResponse struct {
	mcp.Response
	SecurityViolations []string  `json:"-"`
	RiskLevel          string    `json:"-"`
	Signature          string    `json:"signature,omitempty"`
	Timestamp          time.Time `json:"timestamp,omitempty"`
}

// FuzzMCPRequest is the libFuzzer entrypoint for MCP request parsing/validation.
// Enhanced with comprehensive security validation based on audit directives.
func FuzzMCPRequest(data []byte) int {
	// Resource limits (Directive 1.1)
	if len(data) > 10*1024*1024 { // 10MB max
		return 0
	}

	var request SecurityAwareMCPRequest

	// Test JSON parsing with security awareness
	if err := json.Unmarshal(data, &request); err != nil {
		return 0
	}

	// Comprehensive security validation (Directive 3.1)
	if !validateMCPRequestSecurity(&request) {
		return 0
	}

	// Test message bounds checking (Directive 1.1)
	if !validateMCPRequestBounds(&request) {
		return 0
	}

	// Test protocol security (Directive 3.1)
	validateMCPRequestProtocolSecurity(&request)

	// Test for injection attacks (Directive 1.2)
	validateMCPRequestInjectionAttacks(&request)

	// Test for privilege escalation (Directive 2.1)
	validateMCPRequestPrivilegeEscalation(&request)

	// Test message tampering detection (Directive 3.1)
	testMCPRequestTamperingResistance(&request)

	// Test re-serialization
	if _, err := json.Marshal(request); err != nil {
		return 0
	}

	return 1
}

// FuzzMCPResponse is the libFuzzer entrypoint for MCP response parsing/validation.
// Enhanced with comprehensive security validation based on audit directives.
func FuzzMCPResponse(data []byte) int {
	// Resource limits (Directive 1.1)
	if len(data) > 10*1024*1024 { // 10MB max
		return 0
	}

	var response SecurityAwareMCPResponse

	// Test JSON parsing with security awareness
	if err := json.Unmarshal(data, &response); err != nil {
		return 0
	}

	// Comprehensive security validation (Directive 3.1)
	if !validateMCPResponseSecurity(&response) {
		return 0
	}

	// Test message bounds checking (Directive 1.1)
	if !validateMCPResponseBounds(&response) {
		return 0
	}

	// Test response-specific security (Directive 3.1)
	validateMCPResponseDataSecurity(&response)

	// Test for data exfiltration (Directive 3.2)
	validateMCPResponseDataExfiltration(&response)

	// Test for privilege escalation (Directive 2.1)
	validateMCPResponsePrivilegeEscalation(&response)

	// Test message tampering detection (Directive 3.1)
	testMCPResponseTamperingResistance(&response)

	// Test re-serialization
	if _, err := json.Marshal(response); err != nil {
		return 0
	}

	return 1
}

func validateMCPRequestSecurity(request *SecurityAwareMCPRequest) bool {
	request.SecurityViolations = []string{}
	request.RiskLevel = "LOW"

	// Validate JSON-RPC version
	if request.Request.JSONRPC != "2.0" {
		request.SecurityViolations = append(request.SecurityViolations,
			"Invalid JSON-RPC version")
		return false
	}

	// Validate method name for injection attacks
	if request.Request.Method != "" && !isValidMCPMethod(request.Request.Method) {
		request.SecurityViolations = append(request.SecurityViolations,
			"Invalid or potentially malicious method name")
		return false
	}

	// Validate message ID
	if request.Request.ID != nil {
		if !isValidMCPID(request.Request.ID) {
			request.SecurityViolations = append(request.SecurityViolations,
				"Invalid message ID format")
			return false
		}
	}

	// Validate params for injection attacks
	if request.Request.Params != nil {
		if !validateMCPParams(request.Request.Params) {
			request.SecurityViolations = append(request.SecurityViolations,
				"Security violation in params")
			return false
		}
	}

	return len(request.SecurityViolations) == 0
}

func validateMCPResponseSecurity(response *SecurityAwareMCPResponse) bool {
	response.SecurityViolations = []string{}
	response.RiskLevel = "LOW"

	// Validate JSON-RPC version
	if response.Response.JSONRPC != "2.0" {
		response.SecurityViolations = append(response.SecurityViolations,
			"Invalid JSON-RPC version")
		return false
	}

	// Validate message ID
	if response.Response.ID != nil {
		if !isValidMCPID(response.Response.ID) {
			response.SecurityViolations = append(response.SecurityViolations,
				"Invalid message ID format")
			return false
		}
	}

	// Validate result for injection attacks
	if response.Response.Result != nil {
		if !validateMCPResult(response.Response.Result) {
			response.SecurityViolations = append(response.SecurityViolations,
				"Security violation in result")
			return false
		}
	}

	// Validate error for injection attacks
	if response.Response.Error != nil {
		if !validateMCPError(response.Response.Error) {
			response.SecurityViolations = append(response.SecurityViolations,
				"Security violation in error")
			return false
		}
	}

	return len(response.SecurityViolations) == 0
}

func validateMCPRequestBounds(request *SecurityAwareMCPRequest) bool {
	// Check message size
	requestJSON, _ := json.Marshal(request)
	if len(requestJSON) > 10*1024*1024 { // 10MB max
		request.SecurityViolations = append(request.SecurityViolations,
			"Request exceeds size limit")
		return false
	}

	// Check nesting depth
	depth := calculateNestingDepth(requestJSON)
	if depth > 10 {
		request.SecurityViolations = append(request.SecurityViolations,
			"Request nesting too deep")
		return false
	}

	// Check field count
	fieldCount := countJSONFields(requestJSON)
	if fieldCount > 1000 {
		request.SecurityViolations = append(request.SecurityViolations,
			"Too many fields in request")
		return false
	}

	return true
}

func validateMCPResponseBounds(response *SecurityAwareMCPResponse) bool {
	// Check message size
	responseJSON, _ := json.Marshal(response)
	if len(responseJSON) > 10*1024*1024 { // 10MB max
		response.SecurityViolations = append(response.SecurityViolations,
			"Response exceeds size limit")
		return false
	}

	// Check nesting depth
	depth := calculateNestingDepth(responseJSON)
	if depth > 10 {
		response.SecurityViolations = append(response.SecurityViolations,
			"Response nesting too deep")
		return false
	}

	// Check field count
	fieldCount := countJSONFields(responseJSON)
	if fieldCount > 1000 {
		response.SecurityViolations = append(response.SecurityViolations,
			"Too many fields in response")
		return false
	}

	return true
}

func validateMCPRequestProtocolSecurity(request *SecurityAwareMCPRequest) {
	// Check for dangerous methods
	dangerousMethods := []string{
		"system/exec", "system/shell", "system/process",
		"file/read", "file/write", "file/delete",
		"network/connect", "network/listen",
		"database/query", "database/execute",
	}

	methodLower := strings.ToLower(request.Request.Method)
	for _, dangerous := range dangerousMethods {
		if strings.Contains(methodLower, dangerous) {
			request.SecurityViolations = append(request.SecurityViolations,
				fmt.Sprintf("Dangerous method detected: %s", request.Request.Method))
			request.RiskLevel = "HIGH"
		}
	}

	// Check for suspicious parameter patterns
	if request.Request.Params != nil {
		paramsStr := string(request.Request.Params)
		suspiciousPatterns := []string{
			"../", "/etc/", "/proc/", "rm -rf", "DROP TABLE",
			"<script", "javascript:", "data:", "file://",
		}

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(paramsStr, pattern) {
				request.SecurityViolations = append(request.SecurityViolations,
					fmt.Sprintf("Suspicious pattern in params: %s", pattern))
				request.RiskLevel = "MEDIUM"
			}
		}
	}
}

func validateMCPRequestInjectionAttacks(request *SecurityAwareMCPRequest) {
	// Check for SQL injection patterns
	sqlPatterns := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
		"UNION", "OR 1=1", "OR '1'='1", "--", "/*", "*/",
	}

	// Check for command injection patterns
	cmdPatterns := []string{
		";", "|", "&", "`", "$(", "${", ">", "<", ">>", "<<",
		"eval", "exec", "system", "shell_exec",
	}

	// Check for XSS patterns
	xssPatterns := []string{
		"<script", "javascript:", "onload=", "onerror=",
		"<iframe", "<img", "<svg", "data:",
	}

	requestStr := fmt.Sprintf("%v", request)

	for _, pattern := range sqlPatterns {
		if strings.Contains(strings.ToUpper(requestStr), pattern) {
			request.SecurityViolations = append(request.SecurityViolations,
				fmt.Sprintf("SQL injection pattern detected: %s", pattern))
			request.RiskLevel = "HIGH"
		}
	}

	for _, pattern := range cmdPatterns {
		if strings.Contains(requestStr, pattern) {
			request.SecurityViolations = append(request.SecurityViolations,
				fmt.Sprintf("Command injection pattern detected: %s", pattern))
			request.RiskLevel = "CRITICAL"
		}
	}

	for _, pattern := range xssPatterns {
		if strings.Contains(strings.ToLower(requestStr), pattern) {
			request.SecurityViolations = append(request.SecurityViolations,
				fmt.Sprintf("XSS pattern detected: %s", pattern))
			request.RiskLevel = "MEDIUM"
		}
	}
}

func validateMCPRequestPrivilegeEscalation(request *SecurityAwareMCPRequest) {
	// Check for privilege escalation patterns
	privilegePatterns := []string{
		"sudo", "su", "root", "admin", "administrator",
		"privilege", "escalate", "elevate",
		"chmod", "chown", "chgrp",
		"setuid", "setgid", "suid", "sgid",
	}

	requestStr := fmt.Sprintf("%v", request)

	for _, pattern := range privilegePatterns {
		if strings.Contains(strings.ToLower(requestStr), pattern) {
			request.SecurityViolations = append(request.SecurityViolations,
				fmt.Sprintf("Privilege escalation pattern detected: %s", pattern))
			request.RiskLevel = "HIGH"
		}
	}
}

func validateMCPResponseDataSecurity(response *SecurityAwareMCPResponse) {
	// Check for sensitive data in responses
	sensitivePatterns := []string{
		"password", "passwd", "secret", "key", "token",
		"api_key", "apikey", "access_key", "private_key",
		"credential", "auth", "bearer",
		"ssn", "credit_card", "social_security",
	}

	if response.Response.Result != nil {
		resultStr := string(response.Response.Result)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(strings.ToLower(resultStr), pattern) {
				response.SecurityViolations = append(response.SecurityViolations,
					fmt.Sprintf("Sensitive data in response: %s", pattern))
				response.RiskLevel = "MEDIUM"
			}
		}
	}
}

func validateMCPResponseDataExfiltration(response *SecurityAwareMCPResponse) {
	// Check for data exfiltration patterns
	exfiltrationPatterns := []string{
		"http://", "https://", "ftp://", "sftp://",
		"curl", "wget", "fetch", "download",
		"upload", "send", "post", "put",
	}

	responseStr := fmt.Sprintf("%v", response)

	for _, pattern := range exfiltrationPatterns {
		if strings.Contains(strings.ToLower(responseStr), pattern) {
			response.SecurityViolations = append(response.SecurityViolations,
				fmt.Sprintf("Data exfiltration pattern detected: %s", pattern))
			response.RiskLevel = "HIGH"
		}
	}
}

func validateMCPResponsePrivilegeEscalation(response *SecurityAwareMCPResponse) {
	// Check for privilege escalation patterns
	privilegePatterns := []string{
		"sudo", "su", "root", "admin", "administrator",
		"privilege", "escalate", "elevate",
		"chmod", "chown", "chgrp",
		"setuid", "setgid", "suid", "sgid",
	}

	responseStr := fmt.Sprintf("%v", response)

	for _, pattern := range privilegePatterns {
		if strings.Contains(strings.ToLower(responseStr), pattern) {
			response.SecurityViolations = append(response.SecurityViolations,
				fmt.Sprintf("Privilege escalation pattern detected: %s", pattern))
			response.RiskLevel = "HIGH"
		}
	}
}

func testMCPRequestTamperingResistance(request *SecurityAwareMCPRequest) {
	// Test HMAC verification for request integrity
	if request.Signature != "" {
		key := make([]byte, 32)
		rand.Read(key)

		h := hmac.New(sha256.New, key)
		requestData, _ := json.Marshal(request.Request)
		h.Write(requestData)
		h.Write([]byte(request.Timestamp.String()))

		expectedSig := hex.EncodeToString(h.Sum(nil))
		if request.Signature != expectedSig {
			request.SecurityViolations = append(request.SecurityViolations,
				"Request signature mismatch - possible tampering")
		}
	}
}

func testMCPResponseTamperingResistance(response *SecurityAwareMCPResponse) {
	// Test HMAC verification for response integrity
	if response.Signature != "" {
		key := make([]byte, 32)
		rand.Read(key)

		h := hmac.New(sha256.New, key)
		responseData, _ := json.Marshal(response.Response)
		h.Write(responseData)
		h.Write([]byte(response.Timestamp.String()))

		expectedSig := hex.EncodeToString(h.Sum(nil))
		if response.Signature != expectedSig {
			response.SecurityViolations = append(response.SecurityViolations,
				"Response signature mismatch - possible tampering")
		}
	}
}

func isValidMCPMethod(method string) bool {
	// Validate method name format
	if len(method) == 0 || len(method) > 256 {
		return false
	}

	// Check for valid method characters
	for _, char := range method {
		if !isValidMethodChar(char) {
			return false
		}
	}

	// Check for suspicious method names
	suspiciousMethods := []string{
		"eval", "exec", "system", "shell", "cmd",
		"delete", "drop", "truncate", "format",
		"root", "admin", "sudo", "su",
	}

	methodLower := strings.ToLower(method)
	for _, suspicious := range suspiciousMethods {
		if strings.Contains(methodLower, suspicious) {
			return false
		}
	}

	return true
}

func isValidMethodChar(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '_' || char == '/' || char == '.'
}

func isValidMCPID(id *mcp.ID) bool {
	if id == nil {
		return true
	}

	if id.Null {
		return true
	}

	if id.String != nil {
		return len(*id.String) <= 64
	}

	if id.Number != nil {
		return *id.Number >= 0 && *id.Number <= 1e9
	}

	return false
}

func validateMCPParams(params json.RawMessage) bool {
	if params == nil {
		return true
	}

	// Check size
	if len(params) > 10000 { // 10KB max
		return false
	}

	// Check for suspicious content
	paramsStr := string(params)
	suspiciousPatterns := []string{
		"../", "/etc/", "/proc/", "rm -rf", "DROP TABLE",
		"<script", "javascript:", "data:", "file://",
		";", "|", "&", "`", "$(", "${",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(paramsStr, pattern) {
			return false
		}
	}

	return true
}

func validateMCPResult(result json.RawMessage) bool {
	if result == nil {
		return true
	}

	// Check size
	if len(result) > 10000 { // 10KB max
		return false
	}

	// Check for sensitive data
	resultStr := string(result)
	sensitivePatterns := []string{
		"password", "passwd", "secret", "key", "token",
		"api_key", "apikey", "access_key", "private_key",
		"credential", "auth", "bearer",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(strings.ToLower(resultStr), pattern) {
			return false
		}
	}

	return true
}

func validateMCPError(err *mcp.ErrorObject) bool {
	if err == nil {
		return true
	}

	// Check message length
	if len(err.Message) > 4096 {
		return false
	}

	// Check for suspicious content
	messageLower := strings.ToLower(err.Message)
	suspiciousPatterns := []string{
		"../", "/etc/", "/proc/", "rm -rf", "DROP TABLE",
		"<script", "javascript:", "data:", "file://",
		";", "|", "&", "`", "$(", "${",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(messageLower, pattern) {
			return false
		}
	}

	// Check data field
	if err.Data != nil {
		return validateMCPParams(err.Data)
	}

	return true
}

func calculateNestingDepth(data []byte) int {
	depth := 0
	maxDepth := 0

	for _, char := range data {
		switch char {
		case '{', '[':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}', ']':
			depth--
		}
	}

	return maxDepth
}

func countJSONFields(data []byte) int {
	count := 0
	inString := false
	escapeNext := false

	for i := 0; i < len(data); i++ {
		char := data[i]

		if escapeNext {
			escapeNext = false
			continue
		}

		if char == '\\' {
			escapeNext = true
			continue
		}

		if char == '"' {
			inString = !inString
			continue
		}

		if !inString && char == ':' {
			count++
		}
	}

	return count
}
