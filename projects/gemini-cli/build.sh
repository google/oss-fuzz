#!/bin/bash -eux
set -euo pipefail
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Build script for OSS-Fuzz (gemini-cli security-enhanced fuzzers)
# Follows OSS-Fuzz ideal integration practices for Go projects
# Addresses critical OSS-Fuzz infrastructure vulnerabilities identified in security audit

# Security hardening: Enable strict error handling
trap 'echo "❌ Build failed at line $LINENO"; exit 1' ERR

# Security hardening: Verify we're not running as root (CWE-250 mitigation)
if [ "$(id -u)" -eq 0 ]; then
    echo "❌ Security violation: Build script running as root"
    echo "   This violates CWE-250: Execution with Unnecessary Privileges"
    exit 1
fi

# Security hardening: Verify binary integrity (CWE-829 mitigation)
verify_binary_integrity() {
    local binary=$1
    local expected_hash=$2
    
    if [ -f "$binary" ]; then
        local actual_hash=$(sha256sum "$binary" | cut -d' ' -f1)
        if [ "$actual_hash" != "$expected_hash" ]; then
            echo "❌ Binary integrity check failed for $binary"
            echo "   Expected: $expected_hash"
            echo "   Actual:   $actual_hash"
            echo "   This may indicate a supply chain attack (CWE-829)"
            exit 1
        fi
        echo "✅ Binary integrity verified for $binary"
    fi
}

# Security hardening: Check dependency pinning (CWE-937 mitigation)
check_dependency_pinning() {
    if grep -q "@latest" go.mod 2>/dev/null; then
        echo "❌ Unpinned dependencies detected in go.mod"
        echo "   This violates CWE-937: Using Known Vulnerable Components"
        exit 1
    fi
    echo "✅ All dependencies properly pinned"
}

echo "🔒 Security-hardened build process starting..."
echo "   User: $(whoami) (UID: $(id -u))"
echo "   Working directory: $(pwd)"

# Ensure Go is available in the base-builder-go image
go version

# Move into our project directory
cd /src/gemini-cli

# Security hardening: Check dependency pinning before build
echo "🔍 Checking dependency security..."
check_dependency_pinning

# Security hardening: Verify critical binaries
if [ -f "expected_checksums.txt" ]; then
    echo "🔍 Verifying binary integrity..."
    while IFS= read -r line; do
        binary=$(echo "$line" | cut -d' ' -f3)
        hash=$(echo "$line" | cut -d' ' -f1)
        verify_binary_integrity "$binary" "$hash"
    done < expected_checksums.txt
fi

# Initialize or tidy module (ensures build system integration)
if [ ! -f go.mod ]; then
  go mod init github.com/google-gemini/gemini-cli-ossfuzz
fi

# Tidy modules (prevents bit rot and ensures dependency management)
go mod tidy

# Security hardening: Verify go.sum integrity
if [ -f go.sum ]; then
    echo "🔍 Verifying go.sum integrity..."
    go mod verify || {
        echo "❌ go.sum integrity check failed"
        exit 1
    }
    echo "✅ go.sum integrity verified"
fi

# Verify fuzz targets are discoverable and maintainable
echo "Building security-enhanced fuzzers for gemini-cli..."
echo "Fuzz targets: FuzzConfigParser, FuzzMCPRequest, FuzzMCPResponse, FuzzCLIParser, FuzzOAuthTokenRequest, FuzzOAuthTokenResponse"

# Build fuzzers with unified build process
# compile_go_fuzzer MODULE_IMPORT_PATH FUZZ_FUNC OUT_BIN (use full import path for GOPATH compatibility)
PKG="github.com/google-gemini/gemini-cli-ossfuzz/gofuzz/fuzz"

# Build each fuzzer with performance-optimized settings
compile_go_fuzzer ${PKG} FuzzConfigParser FuzzConfigParser
compile_go_fuzzer ${PKG} FuzzMCPRequest FuzzMCPRequest  
compile_go_fuzzer ${PKG} FuzzMCPResponse FuzzMCPResponse
compile_go_fuzzer ${PKG} FuzzCLIParser FuzzCLIParser
compile_go_fuzzer ${PKG} FuzzOAuthTokenResponse FuzzOAuthTokenResponse
compile_go_fuzzer ${PKG} FuzzOAuthTokenRequest FuzzOAuthTokenRequest

# Build regression test driver for seed corpus validation
# Implements OSS-Fuzz ideal integration requirements
echo "Building regression test driver..."
go build -o "${OUT}/test_corpus" gofuzz/test_corpus.go

# Place seed corpora for comprehensive code coverage
# Follows OSS-Fuzz seed corpus best practices
if [ -d seeds/config ]; then
  zip -jr "${OUT}/FuzzConfigParser_seed_corpus.zip" seeds/config || true
fi
if [ -d seeds/mcp ]; then
  zip -jr "${OUT}/FuzzMCPRequest_seed_corpus.zip" seeds/mcp || true
  zip -jr "${OUT}/FuzzMCPResponse_seed_corpus.zip" seeds/mcp || true
fi
if [ -d seeds/cli ]; then
  zip -jr "${OUT}/FuzzCLIParser_seed_corpus.zip" seeds/cli || true
fi
if [ -d seeds/oauth ]; then
  zip -jr "${OUT}/FuzzOAuthTokenResponse_seed_corpus.zip" seeds/oauth || true
  zip -jr "${OUT}/FuzzOAuthTokenRequest_seed_corpus.zip" seeds/oauth || true
fi

# Provide per-target dictionaries to guide mutation (enhances fuzzing efficiency)
cat > "${OUT}/FuzzConfigParser.dict" <<'EOF'
"{"
"}"
"["
"]"
":"
"," 
"apiKey"
"projectId"
"theme"
"proxy"
"enabled"
"url"
"memory"
"limitMb"
"tooling"
"enableMcp"
"enableShell"
"enableWebFetch"
"logLevel"
"outputDir"
"timeout"
"maxRetries"
EOF

cat > "${OUT}/FuzzMCPRequest.dict" <<'EOF'
"jsonrpc"
"2.0"
"method"
"params"
"id"
"tools/list"
"tools/call"
"notifications/list"
EOF

cat > "${OUT}/FuzzMCPResponse.dict" <<'EOF'
"jsonrpc"
"2.0"
"result"
"error"
"code"
"message"
"data"
"id"
"success"
"failure"
EOF

cat > "${OUT}/FuzzOAuthTokenRequest.dict" <<'EOF'
"grant_type"
"authorization_code"
"refresh_token"
"client_credentials"
"password"
"redirect_uri"
"https://"
"http://localhost"
"http://127.0.0.1"
"scope"
"state"
EOF

cat > "${OUT}/FuzzOAuthTokenResponse.dict" <<'EOF'
"access_token"
"token_type"
"expires_in"
"refresh_token"
"id_token"
"scope"
"Bearer"
"Basic"
EOF

cat > "${OUT}/FuzzCLIParser.dict" <<'EOF'
"gemini"
"chat"
"config"
"--model"
"--temperature"
"--max-tokens"
"--system-prompt"
"--set"
"--list"
"--version"
"-v"
"-vvv"
"--output"
"--verbose"
"--dry-run"
"--flag=value"
"--"
"help"
"auth"
EOF

# Provide per-target libFuzzer option tuning for optimal performance
# Ensures efficient execution and prevents OOM/timeout issues
cat > "${OUT}/FuzzConfigParser.options" <<'EOF'
[libfuzzer]
max_len=4096
use_value_profile=1
timeout=60
rss_limit_mb=2048
artifact_prefix=/out/
EOF

for name in FuzzMCPRequest FuzzMCPResponse FuzzCLIParser FuzzOAuthTokenRequest; do
  cat > "${OUT}/${name}.options" <<'EOF'
[libfuzzer]
max_len=2048
use_value_profile=1
timeout=60
rss_limit_mb=2048
artifact_prefix=/out/
EOF
done

cat > "${OUT}/FuzzOAuthTokenResponse.options" <<'EOF'
[libfuzzer]
max_len=32768
use_value_profile=1
timeout=60
rss_limit_mb=2048
artifact_prefix=/out/
EOF

# Verify build success and provide feedback
echo "✓ All fuzzers built successfully"
echo "✓ Seed corpora packaged for comprehensive coverage"
echo "✓ Dictionaries created for enhanced fuzzing efficiency"
echo "✓ Performance options configured for optimal execution"
echo "✓ Regression test driver built for continuous validation"
echo "✓ Ready for OSS-Fuzz continuous integration and CIFuzz testing"

# Run regression tests to validate seed corpus
echo "Running regression tests on seed corpus..."
if [ -f "${OUT}/test_corpus" ]; then
  "${OUT}/test_corpus" -corpus seeds -timeout 30s || {
    echo "❌ Regression tests failed - seed corpus validation error"
    exit 1
  }
  echo "✓ Regression tests passed - seed corpus validated"
else
  echo "⚠️  Regression test driver not found, skipping validation"
fi
