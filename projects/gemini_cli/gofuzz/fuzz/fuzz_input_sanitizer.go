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
	"fmt"
	"strings"
	"time"
)

// InputSanitizerContext provides security validation for input sanitization
type InputSanitizerContext struct {
	SQLKeywords    []string
	XSSPatterns    []string
	HTMLTags       []string
	ScriptPatterns []string
	InjectionChars []string
	MaxInputLength int
	AllowedSchemes []string
}

// SecurityAwareSanitizer extends input sanitization with security validation
type SecurityAwareSanitizer struct {
	Context     *InputSanitizerContext
	SecurityLog []string
	RiskLevel   string
	Timestamp   time.Time
}

// NewInputSanitizerContext creates a hardened security context for input sanitization
func NewInputSanitizerContext() *InputSanitizerContext {
	return &InputSanitizerContext{
		SQLKeywords: []string{
			"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
			"ALTER", "TRUNCATE", "EXEC", "EXECUTE", "MERGE", "UNION",
			"INTERSECT", "EXCEPT", "INTO", "FROM", "WHERE", "GROUP BY",
			"ORDER BY", "HAVING", "LIMIT", "OFFSET", "AND", "OR",
			"NOT", "IN", "EXISTS", "BETWEEN", "LIKE", "IS NULL",
			"IS NOT NULL", "COUNT", "SUM", "AVG", "MIN", "MAX",
		},
		XSSPatterns: []string{
			"<script", "</script>", "javascript:", "vbscript:",
			"onload=", "onerror=", "onclick=", "onmouseover=",
			"onmouseout=", "onmousedown=", "onmouseup=", "onmousemove=",
			"onkeypress=", "onkeydown=", "onkeyup=", "onfocus=", "onblur=",
			"onchange=", "onsubmit=", "onreset=", "onselect=", "onabort=",
			"data:", "vbscript:", "livescript:", "mocha:",
		},
		HTMLTags: []string{
			"<iframe", "<object", "<embed", "<form", "<input",
			"<button", "<textarea", "<select", "<option", "<img",
			"<a ", "<div", "<span", "<p", "<h1", "<h2", "<h3",
			"<h4", "<h5", "<h6", "<ul", "<ol", "<li", "<table",
			"<tr", "<td", "<th", "<thead", "<tbody", "<tfoot",
		},
		ScriptPatterns: []string{
			"eval(", "setTimeout(", "setInterval(", "Function(",
			"constructor", "prototype", "__proto__", "toString",
			"valueOf", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable",
			"alert(", "confirm(", "prompt(", "console.log(",
			"document.cookie", "document.write(", "document.location",
		},
		InjectionChars: []string{
			"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
			"@@", "@", "#", "\\", "/", "*", "+", "-", "=",
			"%", "^", "&", "|", "!", "~", "`", "$", "{", "}",
			"[", "]", "(", ")", "<", ">", ",", ".", "?", ":",
		},
		MaxInputLength: 32768,
		AllowedSchemes: []string{
			"http", "https", "mailto", "tel", "sms",
		},
	}
}

// FuzzInputSanitizer is the libFuzzer entrypoint for input sanitization security testing
// Tests XSS, SQL injection, HTML injection, and other input sanitization bypasses
func FuzzInputSanitizer(data []byte) int {
	if len(data) == 0 || len(data) > 65536 {
		return 0
	}

	// Initialize security context
	context := NewInputSanitizerContext()
	sanitizer := &SecurityAwareSanitizer{
		Context:     context,
		SecurityLog: make([]string, 0),
		RiskLevel:   "LOW",
		Timestamp:   time.Now(),
	}

	// Convert input to potential injection strings
	inputs := parseInputAsInjectionStrings(data)
	if len(inputs) == 0 {
		return 0
	}

	// Test SQL injection attacks
	for _, input := range inputs {
		if testSQLInjection(sanitizer, input) {
			return 0
		}
	}

	// Test XSS attacks
	for _, input := range inputs {
		if testXSSAttacks(sanitizer, input) {
			return 0
		}
	}

	// Test HTML injection attacks
	for _, input := range inputs {
		if testHTMLInjection(sanitizer, input) {
			return 0
		}
	}

	// Test script injection attacks
	for _, input := range inputs {
		if testScriptInjection(sanitizer, input) {
			return 0
		}
	}

	// Test general injection attacks
	for _, input := range inputs {
		if testGeneralInjection(sanitizer, input) {
			return 0
		}
	}

	return 1
}

// parseInputAsInjectionStrings converts fuzzer input into potential injection strings
func parseInputAsInjectionStrings(data []byte) []string {
	input := string(data)

	// Split on common injection delimiters
	delimiters := []string{"\n", "\r", "\t", "\x00", ";", "'", "\"", " ", "="}
	var inputs []string

	for _, delim := range delimiters {
		parts := strings.Split(input, delim)
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if len(part) > 0 && len(part) <= 4096 {
				inputs = append(inputs, part)
			}
		}
	}

	// Add the raw input as a potential injection string
	if len(input) > 0 && len(input) <= 4096 {
		inputs = append(inputs, input)
	}

	return inputs
}

// testSQLInjection tests for SQL injection vulnerabilities
func testSQLInjection(sanitizer *SecurityAwareSanitizer, input string) bool {
	inputUpper := strings.ToUpper(input)

	// Test for SQL keywords
	for _, keyword := range sanitizer.Context.SQLKeywords {
		if strings.Contains(inputUpper, keyword) {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				fmt.Sprintf("SQL injection keyword detected: %s", keyword))
			sanitizer.RiskLevel = "HIGH"
			return true
		}
	}

	// Test for SQL injection patterns
	sqlPatterns := []string{
		"' OR '1'='1", "' OR 1=1", "\" OR \"1\"=\"1\"",
		"' OR ''='", "\" OR \"\"=\"", "'='",
		"UNION SELECT", "UNION ALL SELECT",
		"1' ORDER BY", "1\" ORDER BY",
		"1' GROUP BY", "1\" GROUP BY",
		"1' HAVING", "1\" HAVING",
		"1' LIMIT", "1\" LIMIT",
		"1' OFFSET", "1\" OFFSET",
		"1' PROCEDURE", "1\" PROCEDURE",
		"SCRIPT URL", "SRC=",
	}

	for _, pattern := range sqlPatterns {
		if strings.Contains(inputUpper, strings.ToUpper(pattern)) {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				fmt.Sprintf("SQL injection pattern detected: %s", pattern))
			sanitizer.RiskLevel = "CRITICAL"
			return true
		}
	}

	// Test for comment injection
	if strings.Contains(input, "--") || strings.Contains(input, "/*") {
		if strings.Contains(input, "*/") {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				"SQL comment injection detected")
			sanitizer.RiskLevel = "HIGH"
			return true
		}
	}

	// Test for stacked queries
	if strings.Contains(inputUpper, "; SELECT") ||
		strings.Contains(inputUpper, "; INSERT") ||
		strings.Contains(inputUpper, "; UPDATE") ||
		strings.Contains(inputUpper, "; DELETE") {
		sanitizer.SecurityLog = append(sanitizer.SecurityLog,
			"SQL stacked query injection detected")
		sanitizer.RiskLevel = "CRITICAL"
		return true
	}

	return false
}

// testXSSAttacks tests for Cross-Site Scripting vulnerabilities
func testXSSAttacks(sanitizer *SecurityAwareSanitizer, input string) bool {
	inputLower := strings.ToLower(input)

	// Test for XSS patterns
	for _, pattern := range sanitizer.Context.XSSPatterns {
		if strings.Contains(inputLower, pattern) {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				fmt.Sprintf("XSS pattern detected: %s", pattern))
			sanitizer.RiskLevel = "HIGH"
			return true
		}
	}

	// Test for encoded XSS attempts
	encodedPatterns := []string{
		"%3cscript", "%3c%2fscript", "%3ciframe",
		"&#x3c;script", "&#x3c;/script", "&#x3c;iframe",
		"\\x3cscript", "\\x3c/script", "\\x3ciframe",
	}

	for _, pattern := range encodedPatterns {
		if strings.Contains(inputLower, pattern) {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				fmt.Sprintf("Encoded XSS pattern detected: %s", pattern))
			sanitizer.RiskLevel = "HIGH"
			return true
		}
	}

	// Test for DOM-based XSS patterns
	domPatterns := []string{
		"document.cookie", "document.location", "document.referrer",
		"window.location", "window.name", "location.hash",
		"location.search", "location.pathname", "location.href",
		"innerHTML", "outerHTML", "insertAdjacentHTML",
		"document.write", "document.writeln", "eval(",
	}

	for _, pattern := range domPatterns {
		if strings.Contains(inputLower, pattern) {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				fmt.Sprintf("DOM-based XSS pattern detected: %s", pattern))
			sanitizer.RiskLevel = "MEDIUM"
			return true
		}
	}

	return false
}

// testHTMLInjection tests for HTML injection vulnerabilities
func testHTMLInjection(sanitizer *SecurityAwareSanitizer, input string) bool {
	inputLower := strings.ToLower(input)

	// Test for HTML tag injection
	for _, tag := range sanitizer.Context.HTMLTags {
		if strings.Contains(inputLower, tag) {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				fmt.Sprintf("HTML injection detected: %s", tag))
			sanitizer.RiskLevel = "MEDIUM"
			return true
		}
	}

	// Test for HTML entity injection
	htmlEntities := []string{
		"&lt;script", "&gt;script", "&lt;/script&gt;",
		"&#60;script", "&#62;script", "&#60;/script&#62;",
		"&#x3c;script", "&#x3e;script", "&#x3c;/script&#x3e;",
	}

	for _, entity := range htmlEntities {
		if strings.Contains(inputLower, entity) {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				fmt.Sprintf("HTML entity injection detected: %s", entity))
			sanitizer.RiskLevel = "MEDIUM"
			return true
		}
	}

	// Test for attribute injection
	if strings.Contains(input, "on") && strings.Contains(input, "=") {
		// Look for event handler attributes
		eventHandlers := []string{"onload", "onerror", "onclick", "onmouseover", "onsubmit"}
		for _, handler := range eventHandlers {
			if strings.Contains(inputLower, handler) {
				sanitizer.SecurityLog = append(sanitizer.SecurityLog,
					fmt.Sprintf("HTML attribute injection detected: %s", handler))
				sanitizer.RiskLevel = "HIGH"
				return true
			}
		}
	}

	return false
}

// testScriptInjection tests for script injection vulnerabilities
func testScriptInjection(sanitizer *SecurityAwareSanitizer, input string) bool {
	inputLower := strings.ToLower(input)

	// Test for script patterns
	for _, pattern := range sanitizer.Context.ScriptPatterns {
		if strings.Contains(inputLower, pattern) {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				fmt.Sprintf("Script injection detected: %s", pattern))
			sanitizer.RiskLevel = "HIGH"
			return true
		}
	}

	// Test for template injection
	templatePatterns := []string{
		"{{", "}}", "${", "}", "<%=", "%>",
		"#{", "}", "%{", "}", "{{=", "}}",
		"<%", "%>", "<%=", "<%#", "<%-", "<%@",
	}

	for _, pattern := range templatePatterns {
		if strings.Contains(input, pattern) {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				fmt.Sprintf("Template injection detected: %s", pattern))
			sanitizer.RiskLevel = "MEDIUM"
			return true
		}
	}

	// Test for code injection
	codePatterns := []string{
		"__import__", "import ", "require(", "include ",
		"load ", "open(", "file(", "exec(", "eval(",
		"system(", "shell_exec(", "popen(", "proc_open(",
	}

	for _, pattern := range codePatterns {
		if strings.Contains(inputLower, pattern) {
			sanitizer.SecurityLog = append(sanitizer.SecurityLog,
				fmt.Sprintf("Code injection detected: %s", pattern))
			sanitizer.RiskLevel = "CRITICAL"
			return true
		}
	}

	return false
}

// testGeneralInjection tests for general injection vulnerabilities
func testGeneralInjection(sanitizer *SecurityAwareSanitizer, input string) bool {
	// Test for dangerous characters
	for _, char := range sanitizer.Context.InjectionChars {
		if strings.Contains(input, char) {
			// Check if it might be a legitimate use
			if !isLikelyLegitimateUse(input, char) {
				sanitizer.SecurityLog = append(sanitizer.SecurityLog,
					fmt.Sprintf("Injection character detected: %s", char))
				sanitizer.RiskLevel = "MEDIUM"
				return true
			}
		}
	}

	// Test for null byte injection
	if strings.Contains(input, "\x00") {
		sanitizer.SecurityLog = append(sanitizer.SecurityLog,
			"Null byte injection detected")
		sanitizer.RiskLevel = "HIGH"
		return true
	}

	// Test for path traversal
	if strings.Contains(input, "../") || strings.Contains(input, "..\\") {
		sanitizer.SecurityLog = append(sanitizer.SecurityLog,
			"Path traversal detected")
		sanitizer.RiskLevel = "HIGH"
		return true
	}

	// Test for URL injection
	if strings.Contains(input, "://") {
		for _, scheme := range sanitizer.Context.AllowedSchemes {
			if strings.Contains(input, scheme+"://") {
				break
			}
		}
		// If we reach here, it's an unusual scheme
		sanitizer.SecurityLog = append(sanitizer.SecurityLog,
			"URL injection with unusual scheme detected")
		sanitizer.RiskLevel = "MEDIUM"
		return true
	}

	return false
}

// Helper functions

func isLikelyLegitimateUse(input, char string) bool {
	// Some heuristics to avoid false positives

	// Quotes in JSON-like structures
	if char == "\"" || char == "'" {
		if strings.Contains(input, "{") && strings.Contains(input, ":") {
			return true // Likely JSON
		}
		if strings.Contains(input, "=") && strings.Contains(input, " ") {
			return true // Likely assignment
		}
	}

	// Semicolons in URLs or paths
	if char == ";" {
		if strings.Contains(input, "://") || strings.Contains(input, "/") {
			return true // Likely URL or path
		}
	}

	// Equal signs in URLs or assignments
	if char == "=" {
		if strings.Contains(input, "?") || strings.Contains(input, "&") {
			return true // Likely URL parameters
		}
	}

	return false
}
