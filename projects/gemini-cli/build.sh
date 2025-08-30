#!/bin/bash -eux
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

# Build script for OSS-Fuzz (gemini-cli mirrored-parsers in Go)

# Ensure Go is available in the base-builder-go image
go version

# Move into our project directory
cd /src/gemini-cli

# Initialize or tidy module
if [ ! -f go.mod ]; then
  go mod init github.com/google-gemini/gemini-cli-ossfuzz
fi

# Tidy modules (in case)
go mod tidy

# Build fuzzers
# compile_go_fuzzer MODULE_IMPORT_PATH FUZZ_FUNC OUT_BIN (use full import path for GOPATH compatibility)
PKG="github.com/google-gemini/gemini-cli-ossfuzz/gofuzz/fuzz"
compile_go_fuzzer ${PKG} FuzzConfigParser FuzzConfigParser
compile_go_fuzzer ${PKG} FuzzMCPRequest FuzzMCPRequest
compile_go_fuzzer ${PKG} FuzzMCPResponse FuzzMCPResponse
compile_go_fuzzer ${PKG} FuzzCLIParser FuzzCLIParser
compile_go_fuzzer ${PKG} FuzzOAuthTokenResponse FuzzOAuthTokenResponse
compile_go_fuzzer ${PKG} FuzzOAuthTokenRequest FuzzOAuthTokenRequest

# Place seed corpora if present
if [ -d seeds/config ]; then
  zip -jr "${OUT}/FuzzConfigParser_seed_corpus.zip" seeds/config || true
fi
if [ -d seeds/mcp ]; then
  zip -jr "${OUT}/FuzzMCPRequest_seed_corpus.zip" seeds/mcp || true
  zip -jr "${OUT}/FuzzMCPResponse_seed_corpus.zip" seeds/mcp || true
fi

# Provide per-target dictionaries to guide mutation
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
EOF

cat > "${OUT}/FuzzOAuthTokenResponse.dict" <<'EOF'
"access_token"
"token_type"
"expires_in"
"refresh_token"
"id_token"
"scope"
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
EOF

# Provide per-target libFuzzer option tuning
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
if [ -d seeds/cli ]; then
  zip -jr "${OUT}/FuzzCLIParser_seed_corpus.zip" seeds/cli || true
fi
if [ -d seeds/oauth ]; then
  zip -jr "${OUT}/FuzzOAuthTokenResponse_seed_corpus.zip" seeds/oauth || true
  zip -jr "${OUT}/FuzzOAuthTokenRequest_seed_corpus.zip" seeds/oauth || true
fi
