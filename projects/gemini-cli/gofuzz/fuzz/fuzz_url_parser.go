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
	"net/url"
	"regexp"
	"strings"
	"time"
)

// URLSecurityContext provides security validation for URL operations
type URLSecurityContext struct {
	AllowedSchemes    []string
	BlockedSchemes    []string
	AllowedDomains    []string
	BlockedDomains    []string
	AllowedPorts      []int
	BlockedPorts      []int
	MaxURLLength      int
	MaxQueryLength    int
	MaxFragmentLength int
}

// SecurityAwareURLParser extends URL parsing with security validation
type SecurityAwareURLParser struct {
	Context     *URLSecurityContext
	SecurityLog []string
	RiskLevel   string
	Timestamp   time.Time
}

// NewURLSecurityContext creates a hardened security context for URL parsing
func NewURLSecurityContext() *URLSecurityContext {
	return &URLSecurityContext{
		AllowedSchemes: []string{
			"http", "https", "ftp", "ftps",
		},
		BlockedSchemes: []string{
			"javascript", "data", "file", "chrome",
			"chrome-extension", "about", "chrome-devtools",
			"jar", "chrome-search", "chrome-settings",
		},
		AllowedDomains: []string{
			"localhost", "127.0.0.1", "::1",
			"example.com", "test.com",
		},
		BlockedDomains: []string{
			"169.254.169.254", "metadata.google.internal",
			"127.0.0.1", "0.0.0.0", "localhost",
			"internal", "local", "private",
		},
		AllowedPorts: []int{80, 443, 21, 22, 25, 53, 110, 143, 993, 995},
		BlockedPorts: []int{0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 23, 37, 42, 43,
			69, 77, 79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115,
			117, 119, 123, 135, 139, 143, 179, 389, 512, 513, 514, 515, 526,
			530, 531, 532, 540, 556, 563, 587, 601, 636, 993, 995, 2049, 3659,
			4045, 6000, 6665, 6666, 6667, 6668, 6669, 6697},
		MaxURLLength:      4096,
		MaxQueryLength:    2048,
		MaxFragmentLength: 1024,
	}
}

// FuzzURLParser is the libFuzzer entrypoint for URL parsing security testing
// Tests URL parsing, SSRF attacks, and URL-based attack vectors
func FuzzURLParser(data []byte) int {
	if len(data) == 0 || len(data) > 8192 {
		return 0
	}

	// Initialize security context
	context := NewURLSecurityContext()
	parser := &SecurityAwareURLParser{
		Context:     context,
		SecurityLog: make([]string, 0),
		RiskLevel:   "LOW",
		Timestamp:   time.Now(),
	}

	// Convert input to potential URLs
	urls := parseInputAsURLs(data)
	if len(urls) == 0 {
		return 0
	}

	// Test URL parsing security
	for _, testURL := range urls {
		if testURLParsingSecurity(parser, testURL) {
			return 0
		}
	}

	// Test SSRF attacks
	for _, testURL := range urls {
		if testSSRFAttacks(parser, testURL) {
			return 0
		}
	}

	// Test URL-based injection attacks
	for _, testURL := range urls {
		if testURLInjectionAttacks(parser, testURL) {
			return 0
		}
	}

	// Test URL encoding attacks
	for _, testURL := range urls {
		if testURLEncodingAttacks(parser, testURL) {
			return 0
		}
	}

	// Test domain validation
	for _, testURL := range urls {
		if testDomainValidation(parser, testURL) {
			return 0
		}
	}

	return 1
}

// parseInputAsURLs converts fuzzer input into potential URLs
func parseInputAsURLs(data []byte) []string {
	input := string(data)

	// Common URL patterns to extract
	urlPatterns := []string{
		`https?://[^\s<>"{}|\\^]+`,
		`ftp://[^\s<>"{}|\\^]+`,
		`javascript:[^\s<>"{}|\\^]+`,
		`data:[^\s<>"{}|\\^]+`,
		`file://[^\s<>"{}|\\^]+`,
	}

	var urls []string
	for _, pattern := range urlPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(input, -1)
		urls = append(urls, matches...)
	}

	// Also add the raw input as a potential URL
	if len(input) > 0 && len(input) <= 4096 {
		urls = append(urls, input)
	}

	return urls
}

// testURLParsingSecurity tests URL parsing security
func testURLParsingSecurity(parser *SecurityAwareURLParser, rawURL string) bool {
	// Test URL parsing
	parsed, err := url.Parse(rawURL)
	if err != nil {
		// This is expected for malformed URLs
		return false
	}

	// Test for dangerous schemes
	for _, blocked := range parser.Context.BlockedSchemes {
		if parsed.Scheme == blocked {
			parser.SecurityLog = append(parser.SecurityLog,
				fmt.Sprintf("Blocked scheme detected: %s", rawURL))
			parser.RiskLevel = "CRITICAL"
			return true
		}
	}

	// Test URL length limits
	if len(rawURL) > parser.Context.MaxURLLength {
		parser.SecurityLog = append(parser.SecurityLog,
			fmt.Sprintf("URL too long: %d characters", len(rawURL)))
		parser.RiskLevel = "MEDIUM"
		return true
	}

	// Test query length
	if len(parsed.RawQuery) > parser.Context.MaxQueryLength {
		parser.SecurityLog = append(parser.SecurityLog,
			fmt.Sprintf("Query too long: %d characters", len(parsed.RawQuery)))
		parser.RiskLevel = "MEDIUM"
		return true
	}

	// Test fragment length
	if len(parsed.Fragment) > parser.Context.MaxFragmentLength {
		parser.SecurityLog = append(parser.SecurityLog,
			fmt.Sprintf("Fragment too long: %d characters", len(parsed.Fragment)))
		parser.RiskLevel = "MEDIUM"
		return true
	}

	return false
}

// testSSRFAttacks tests Server-Side Request Forgery attacks
func testSSRFAttacks(parser *SecurityAwareURLParser, rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	hostname := strings.ToLower(parsed.Hostname())

	// Test for cloud metadata services
	metadataServices := []string{
		"169.254.169.254",           // AWS metadata
		"metadata.google.internal",  // GCP metadata
		"metadata",                  // Azure metadata
		"instance-data",             // DigitalOcean metadata
		"api.service.softlayer.com", // IBM Cloud metadata
	}

	for _, service := range metadataServices {
		if hostname == service || strings.Contains(hostname, service) {
			parser.SecurityLog = append(parser.SecurityLog,
				fmt.Sprintf("Metadata service access attempt: %s", rawURL))
			parser.RiskLevel = "CRITICAL"
			return true
		}
	}

	// Test for private IP ranges
	if isPrivateIP(hostname) {
		parser.SecurityLog = append(parser.SecurityLog,
			fmt.Sprintf("Private IP access attempt: %s", rawURL))
		parser.RiskLevel = "HIGH"
		return true
	}

	// Test for localhost access
	if hostname == "localhost" || hostname == "127.0.0.1" ||
		hostname == "::1" || strings.HasPrefix(hostname, "127.") {
		parser.SecurityLog = append(parser.SecurityLog,
			fmt.Sprintf("Localhost access attempt: %s", rawURL))
		parser.RiskLevel = "HIGH"
		return true
	}

	return false
}

// testURLInjectionAttacks tests URL-based injection attacks
func testURLInjectionAttacks(parser *SecurityAwareURLParser, rawURL string) bool {
	// Test for script injection in URLs
	scriptPatterns := []string{
		"<script", "</script>", "javascript:", "data:",
		"vbscript:", "livescript:", "mocha:", "eval(",
		"setTimeout(", "setInterval(", "Function(",
	}

	rawURLLower := strings.ToLower(rawURL)
	for _, pattern := range scriptPatterns {
		if strings.Contains(rawURLLower, pattern) {
			parser.SecurityLog = append(parser.SecurityLog,
				fmt.Sprintf("Script injection in URL: %s", rawURL))
			parser.RiskLevel = "CRITICAL"
			return true
		}
	}

	// Test for SQL injection in URL
	sqlPatterns := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
		"UNION", "OR 1=1", "OR '1'='1", "--", "/*", "*/",
		"xp_cmdshell", "sp_executesql", "exec(", "execute(",
	}

	for _, pattern := range sqlPatterns {
		if strings.Contains(strings.ToUpper(rawURL), pattern) {
			parser.SecurityLog = append(parser.SecurityLog,
				fmt.Sprintf("SQL injection in URL: %s", rawURL))
			parser.RiskLevel = "CRITICAL"
			return true
		}
	}

	// Test for command injection in URL
	cmdPatterns := []string{
		";", "|", "&", "`", "$(", "${", "&&", "||",
		"eval", "exec", "system", "shell_exec", "popen",
		"proc_open", "passthru", "shell", "bash", "sh",
	}

	for _, pattern := range cmdPatterns {
		if strings.Contains(rawURL, pattern) {
			parser.SecurityLog = append(parser.SecurityLog,
				fmt.Sprintf("Command injection in URL: %s", rawURL))
			parser.RiskLevel = "CRITICAL"
			return true
		}
	}

	return false
}

// testURLEncodingAttacks tests URL encoding attacks
func testURLEncodingAttacks(parser *SecurityAwareURLParser, rawURL string) bool {
	// Test for double encoding attacks
	doubleEncoded := strings.Contains(rawURL, "%25") ||
		strings.Contains(rawURL, "%2F") ||
		strings.Contains(rawURL, "%2E")

	if doubleEncoded {
		parser.SecurityLog = append(parser.SecurityLog,
			fmt.Sprintf("Double encoding attack: %s", rawURL))
		parser.RiskLevel = "HIGH"
		return true
	}

	// Test for overlong UTF-8 sequences
	if strings.Contains(rawURL, "%C0%") || strings.Contains(rawURL, "%C1%") {
		parser.SecurityLog = append(parser.SecurityLog,
			fmt.Sprintf("Overlong UTF-8 attack: %s", rawURL))
		parser.RiskLevel = "HIGH"
		return true
	}

	// Test for null byte attacks
	if strings.Contains(rawURL, "%00") || strings.Contains(rawURL, "\x00") {
		parser.SecurityLog = append(parser.SecurityLog,
			fmt.Sprintf("Null byte attack: %s", rawURL))
		parser.RiskLevel = "HIGH"
		return true
	}

	return false
}

// testDomainValidation tests domain validation security
func testDomainValidation(parser *SecurityAwareURLParser, rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return false
	}

	// Test for domain homograph attacks
	if containsURLHomographAttack(hostname) {
		parser.SecurityLog = append(parser.SecurityLog,
			fmt.Sprintf("Domain homograph attack: %s", rawURL))
		parser.RiskLevel = "HIGH"
		return true
	}

	// Test for blocked domains
	for _, blocked := range parser.Context.BlockedDomains {
		if hostname == blocked || strings.Contains(hostname, blocked) {
			parser.SecurityLog = append(parser.SecurityLog,
				fmt.Sprintf("Blocked domain access: %s", rawURL))
			parser.RiskLevel = "HIGH"
			return true
		}
	}

	// Test for unusual port numbers
	if parsed.Port() != "" {
		// This would check port against allowed/blocked lists
		parser.SecurityLog = append(parser.SecurityLog,
			fmt.Sprintf("Port-specific access: %s", rawURL))
		parser.RiskLevel = "MEDIUM"
		return true
	}

	return false
}

// Helper functions

func isPrivateIP(hostname string) bool {
	// Check for private IPv4 ranges
	privateRanges := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
		"172.30.", "172.31.", "192.168.", "169.254.",
	}

	for _, prefix := range privateRanges {
		if strings.HasPrefix(hostname, prefix) {
			return true
		}
	}

	return false
}

func containsURLHomographAttack(domain string) bool {
	// Check for mixed script domains (basic homograph detection)
	hasLatin := false
	hasCyrillic := false
	hasGreek := false

	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLatin = true
		}
		if r >= 0x0400 && r <= 0x04FF {
			hasCyrillic = true
		}
		if r >= 0x0370 && r <= 0x03FF {
			hasGreek = true
		}
	}

	// If domain contains multiple scripts, it might be a homograph attack
	scriptCount := 0
	if hasLatin {
		scriptCount++
	}
	if hasCyrillic {
		scriptCount++
	}
	if hasGreek {
		scriptCount++
	}

	return scriptCount > 1
}
