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

OSS-Fuzz integration for security testing of the Gemini CLI project.

## Fuzz Targets

### Core Targets (11 total)
- **FuzzConfigParser**: JSON config parsing with injection prevention
- **FuzzCLIParser**: CLI argument parsing with security validation
- **FuzzMCPRequest**: MCP protocol request validation
- **FuzzMCPResponse**: MCP protocol response validation
- **FuzzOAuthTokenRequest**: OAuth token request security
- **FuzzOAuthTokenResponse**: OAuth token response validation

### Security Targets
- **FuzzFileSystemOperations**: Path traversal and file system security
- **FuzzURLParser**: URL parsing with SSRF protection
- **FuzzCryptoOperations**: Cryptographic operations validation
- **FuzzEnvironmentParser**: Environment variable security
- **FuzzInputSanitizer**: XSS/SQL injection prevention

## Security Coverage

Covers 15+ attack categories including:
- Command injection
- Path traversal
- JSON injection
- OAuth security
- Unicode attacks
- File system security
- URL security
- Cryptographic vulnerabilities
- Environment injection
- Input sanitization

## Building

```bash
# Build all fuzz targets
./build.sh

# Test build
docker build -t gemini-cli-fuzz .
```

## Project Structure

```
├── build.sh              # Build script
├── Dockerfile            # Container configuration
├── project.yaml          # OSS-Fuzz configuration
├── fuzzers/              # JavaScript fuzz targets
├── gofuzz/               # Go fuzz targets
├── seeds/                # Test corpora
└── src/                  # Source code
```
