#!/bin/bash -eux
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
