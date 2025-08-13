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
# compile_go_fuzzer MODULE_PATH PACKAGE FUZZ_FUNC OUT_BIN
compile_go_fuzzer ./gofuzz/fuzz fuzz FuzzConfigParser FuzzConfigParser
compile_go_fuzzer ./gofuzz/fuzz fuzz FuzzMCPDecoder FuzzMCPDecoder
compile_go_fuzzer ./gofuzz/fuzz fuzz FuzzCLIParser FuzzCLIParser
compile_go_fuzzer ./gofuzz/fuzz fuzz FuzzOAuthTokenResponse FuzzOAuthTokenResponse
compile_go_fuzzer ./gofuzz/fuzz fuzz FuzzOAuthTokenRequest FuzzOAuthTokenRequest

# Place seed corpora if present
if [ -d seeds/config ]; then
  zip -jr "${OUT}/FuzzConfigParser_seed_corpus.zip" seeds/config || true
fi
if [ -d seeds/mcp ]; then
  zip -jr "${OUT}/FuzzMCPDecoder_seed_corpus.zip" seeds/mcp || true
fi
if [ -d seeds/cli ]; then
  zip -jr "${OUT}/FuzzCLIParser_seed_corpus.zip" seeds/cli || true
fi
if [ -d seeds/oauth ]; then
  zip -jr "${OUT}/FuzzOAuthTokenResponse_seed_corpus.zip" seeds/oauth || true
  zip -jr "${OUT}/FuzzOAuthTokenRequest_seed_corpus.zip" seeds/oauth || true
fi
