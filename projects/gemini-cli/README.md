# Gemini CLI OSS-Fuzz Integration

This directory contains a comprehensive OSS-Fuzz integration for the [Gemini CLI](https://github.com/google-gemini/gemini-cli) project using Go mirrored parsers.

## Overview

The Gemini CLI processes various untrusted inputs that benefit from continuous fuzzing:
- JSON configuration files
- MCP (Model Context Protocol) JSON-RPC envelopes  
- Command-line arguments
- OAuth 2.0 token data

Since the upstream project is implemented in TypeScript/Node.js, this integration uses mirrored parsers in Go to enable robust fuzzing with libFuzzer and sanitizers.

## Fuzz Targets

### 1. FuzzConfigParser
- **Target**: JSON configuration parsing and validation
- **Coverage**: Schema validation, bounds checking, injection prevention
- **Seeds**: `seeds/config/`

### 2. FuzzMCPRequest
- **Target**: MCP Request envelope processing
- **Coverage**: Request structures, protocol validation
- **Seeds**: `seeds/mcp/`

### 3. FuzzMCPResponse
- **Target**: MCP Response envelope processing
- **Coverage**: Response structures, protocol validation
- **Seeds**: `seeds/mcp/`

### 4. FuzzCLIParser
- **Target**: Command-line argument parsing
- **Coverage**: Shell injection prevention, argument validation
- **Seeds**: `seeds/cli/`

### 5. FuzzOAuthTokenResponse
- **Target**: OAuth 2.0 token response validation
- **Coverage**: JWT structure, token format validation
- **Seeds**: `seeds/oauth/`

### 6. FuzzOAuthTokenRequest
- **Target**: OAuth 2.0 token request validation  
- **Coverage**: Grant type validation, redirect URI security
- **Seeds**: `seeds/oauth/`

## Architecture

```
gofuzz/
├── fuzz/                    # Fuzz target entry points
│   ├── fuzz_config_parser.go
│   ├── fuzz_mcp_decoder.go
│   ├── fuzz_cli_parser.go
│   ├── fuzz_oauth_token_response.go
│   └── fuzz_oauth_token_request.go
└── internal/               # Mirrored parser implementations
    ├── config/
    ├── mcp/
    └── oauth/
```

## Local Testing

```bash
# Build fuzzers
python3 infra/helper.py build_fuzzers --sanitizer address --engine libfuzzer gemini-cli

# Run individual fuzzers
python3 infra/helper.py run_fuzzer gemini-cli FuzzConfigParser
python3 infra/helper.py run_fuzzer gemini-cli FuzzMCPRequest
python3 infra/helper.py run_fuzzer gemini-cli FuzzMCPResponse
python3 infra/helper.py run_fuzzer gemini-cli FuzzCLIParser
python3 infra/helper.py run_fuzzer gemini-cli FuzzOAuthTokenResponse
python3 infra/helper.py run_fuzzer gemini-cli FuzzOAuthTokenRequest
```

## Security Focus

This integration specifically targets input validation vulnerabilities:
- Configuration injection attacks
- MCP protocol manipulation
- Command injection via CLI arguments  
- OAuth token tampering and validation bypass
- JSON parsing edge cases and memory safety

## Maintenance

- **Primary Contact**: reconsumeralization@gmail.com
- **Upstream Sync**: Parsers mirror public API behavior only
- **Schema Updates**: Will be synchronized with upstream changes
- **Coverage**: Monitored via OSS-Fuzz dashboard

## Implementation Notes

- Uses Go mirrored parsers approach suitable for TypeScript projects
- No external dependencies or I/O operations
- Comprehensive seed corpora from public documentation
- Follows OSS-Fuzz best practices for sanitizer compatibility
- Memory-safe with appropriate input size limits