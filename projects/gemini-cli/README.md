<!-- Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. -->

# Gemini CLI OSS-Fuzz Integration

This directory contains the OSS-Fuzz integration for the Gemini CLI project, providing comprehensive security testing through automated fuzzing.

## Overview

The Gemini CLI OSS-Fuzz integration delivers enterprise-grade security validation through continuous automated testing. This integration proactively identifies vulnerabilities across critical application components, ensuring robust security posture for production deployments.

## Fuzzer Targets

The integration includes 11 comprehensive fuzz targets covering all major attack surfaces:

### Core Application Fuzzers
- **FuzzConfigParser**: Configuration file parsing and validation with injection prevention
- **FuzzCLIParser**: Command-line argument parsing with security hardening
- **FuzzMCPRequest**: MCP protocol request handling and validation
- **FuzzMCPResponse**: MCP protocol response processing security
- **FuzzOAuthTokenRequest**: OAuth token request processing with CSRF protection
- **FuzzOAuthTokenResponse**: OAuth token response validation and security

### Security-Focused Fuzzers
- **FuzzFileSystemOperations**: File system security and path traversal prevention
- **FuzzURLParser**: URL parsing with SSRF (Server-Side Request Forgery) protection
- **FuzzCryptoOperations**: Cryptographic operations and weak algorithm detection
- **FuzzEnvironmentParser**: Environment variable security and injection prevention
- **FuzzInputSanitizer**: XSS, SQL injection, and HTML injection defense

## Security Coverage

### Attack Surface Protection (15+ Categories)
- ✅ **Command Injection**: Shell metacharacter detection and sanitization
- ✅ **Path Traversal**: File system access control with boundary validation
- ✅ **JSON Injection**: Malformed JSON handling and protocol security
- ✅ **OAuth Security**: Token validation, CSRF protection, and timing attack prevention
- ✅ **Unicode Security**: Homograph attacks and bidirectional text detection
- ✅ **Resource Limits**: Memory, execution time, and file handle constraints
- ✅ **File System Security**: Access control and race condition prevention
- ✅ **URL Security**: SSRF protection and input validation
- ✅ **Cryptographic Security**: Weak algorithm detection and secure key management
- ✅ **Environment Security**: Variable injection and privilege escalation prevention
- ✅ **Input Sanitization**: XSS, SQL injection, and HTML injection defense
- ✅ **Supply Chain Protection**: Dependency and command hijacking prevention
- ✅ **Timing Attack Prevention**: Constant-time comparison implementation
- ✅ **Template Injection**: Server-side template injection detection
- ✅ **Code Injection**: Remote code execution and eval() abuse prevention

### Compliance Standards
- **OWASP Top 10**: Complete coverage including injection flaws and broken access control
- **CWE Coverage**: 50+ Common Weakness Enumerations addressed
- **NIST Cybersecurity Framework**: Comprehensive Identify, Protect, Detect implementation

## Build and Execution

### Building Fuzzers
