// Copyright 2025 Google LLC
// Shell command validation fuzzer - Critical security component

//go:build gofuzz
// +build gofuzz

package fuzz

import (
	"encoding/json"
	"regexp"
	"strings"
)

// FuzzShellValidation tests for command injection vulnerabilities
func FuzzShellValidation(data []byte) int {
	// Parse as JSON for structured testing
	var input struct {
		Command   string   `json:"command"`
		Args      []string `json:"args"`
		Allowlist []string `json:"allowlist"`
		Shell     string   `json:"shell"`
	}
	
	if err := json.Unmarshal(data, &input); err != nil {
		// Fall back to raw command testing
		return fuzzRawCommand(string(data))
	}
	
	// Test command injection patterns
	if containsShellInjection(input.Command) {
		return 1 // Interesting input found
	}	
	// Test argument injection
	for _, arg := range input.Args {
		if containsShellInjection(arg) {
			return 1
		}
	}
	
	// Test allowlist bypass
	if len(input.Allowlist) > 0 {
		if bypassesAllowlist(input.Command, input.Allowlist) {
			return 1 // Allowlist bypass detected
		}
	}
	
	// Test shell-specific injections
	switch input.Shell {
	case "bash", "sh":
		if containsBashInjection(input.Command) {
			return 1
		}
	case "powershell", "cmd":
		if containsPowerShellInjection(input.Command) {
			return 1
		}
	}
	
	return 0
}

// containsShellInjection checks for common injection patterns
func containsShellInjection(cmd string) bool {
	// Critical injection patterns
	patterns := []string{		"&&", "||", ";", "|",           // Command chaining
		"$(", "`",                       // Command substitution
		">", ">>", "<",                  // Redirection
		"&", "2>", "2>&1",              // Background/stderr
		"\n", "\r",                      // Newline injection
		"${", "%(", "$(",                // Variable expansion
		"eval", "exec", "system",        // Direct execution
		"/bin/sh", "/bin/bash", "cmd",   // Shell invocation
		"nc ", "curl ", "wget ",         // Network tools
		"rm -rf", "dd if=", "mkfs",     // Destructive commands
	}
	
	cmdLower := strings.ToLower(cmd)
	for _, pattern := range patterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}
	
	// Check for encoded patterns
	if containsEncodedInjection(cmd) {
		return true
	}
	
	return false
}

// containsBashInjection checks for bash-specific injections
func containsBashInjection(cmd string) bool {
	bashPatterns := []string{
		"$IFS", "${IFS}",                // Internal Field Separator abuse		"$'", "$\"",                     // ANSI-C quoting
		"!(", "[[", "]]",                // Bash conditionals
		"source ", ". ",                 // Source command
		"/dev/tcp/", "/dev/udp/",        // Network pseudo-devices
		">{", "}&",                      // Process substitution
		"<<<", "<<-",                    // Here strings/docs
	}
	
	for _, pattern := range bashPatterns {
		if strings.Contains(cmd, pattern) {
			return true
		}
	}
	
	return false
}

// containsPowerShellInjection checks for PowerShell-specific injections
func containsPowerShellInjection(cmd string) bool {
	psPatterns := []string{
		"Invoke-Expression", "IEX",
		"Invoke-Command", 
		"Start-Process",
		"-EncodedCommand",
		"[System.Diagnostics.Process]",
		"New-Object System",
		"powershell.exe",
		"-ExecutionPolicy Bypass",
	}
	
	cmdLower := strings.ToLower(cmd)	for _, pattern := range psPatterns {
		if strings.Contains(cmdLower, strings.ToLower(pattern)) {
			return true
		}
	}
	
	return false
}

// containsEncodedInjection checks for encoded injection attempts
func containsEncodedInjection(cmd string) bool {
	// Check for hex encoding
	hexPattern := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	if hexPattern.MatchString(cmd) {
		return true
	}
	
	// Check for Unicode encoding
	unicodePattern := regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	if unicodePattern.MatchString(cmd) {
		return true
	}
	
	// Check for base64 patterns (common lengths)
	base64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	if base64Pattern.MatchString(cmd) {
		// Could be base64 encoded command
		return true
	}
	
	return false