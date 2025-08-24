#!/bin/bash -eu
# Copyright 2025 Google LLC
# Enhanced build script for OSS-Fuzz with comprehensive dual-language support

set -euxo pipefail  # Enhanced error handling

echo "=== Gemini CLI OSS-Fuzz Build Script ==="
echo "Building dual-language fuzzers targeting Issue #1121 and other critical vulnerabilities"

# Environment setup
export CGO_ENABLED=1  # Enable CGO for sanitizers
export GOPROXY=https://proxy.golang.org,direct
export GOSUMDB=sum.golang.org

# Verify environment
echo "Build environment:"
echo "  SRC=$SRC"
echo "  OUT=$OUT"
echo "  CC=$CC"
echo "  CXX=$CXX"
echo "  CFLAGS=$CFLAGS"
echo "  CXXFLAGS=$CXXFLAGS"
echo "  LIB_FUZZING_ENGINE=$LIB_FUZZING_ENGINE"

# Clone upstream repository if not present
if [ ! -d "$SRC/gemini-cli-upstream" ]; then
  echo "Cloning upstream repository for reference..."
  git clone --depth 1 https://github.com/google-gemini/gemini-cli.git "$SRC/gemini-cli-upstream"
fi

# Navigate to project directory
cd "$SRC/gemini-cli"
# Build Go fuzzers
echo "=== Building Go Fuzz Targets ==="
cd "$SRC/gemini-cli/gofuzz"

# Download dependencies
go mod download
go mod verify

# Critical security fuzzers (Priority 1 - Issue #1121)
echo "Building critical security fuzzers..."
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzSymlinkValidation fuzz_symlink_validation
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzPathValidation fuzz_path_validation
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzContextFileParser fuzz_context_file_parser
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzShellValidation fuzz_shell_validation

# Core functionality fuzzers (Priority 2)
echo "Building core functionality fuzzers..."
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzConfigParser fuzz_config_parser
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzCLIParser fuzz_cli_parser
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzFileSystemOperations fuzz_file_system_operations
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzInputSanitizer fuzz_input_sanitizer

# Protocol fuzzers (Priority 3)
echo "Building protocol fuzzers..."
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzMCPDecoder fuzz_mcp_decoder
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzMCPRequest fuzz_mcp_request
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzMCPResponse fuzz_mcp_response
# Authentication fuzzers (Priority 4)
echo "Building authentication fuzzers..."
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzOAuthTokenRequest fuzz_oauth_token_request
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzOAuthTokenResponse fuzz_oauth_token_response

# Additional fuzzers
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzURLParser fuzz_url_parser
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzCryptoOperations fuzz_crypto_operations
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzEnvironmentParser fuzz_environment_parser
compile_go_fuzzer github.com/google-gemini/gemini-cli/gofuzz/fuzz FuzzSlashCommands fuzz_slash_commands

cd "$SRC/gemini-cli"

# Build JavaScript fuzzers
echo "=== Building JavaScript Fuzz Targets ==="
cd "$SRC/gemini-cli/fuzzers"

# Install dependencies
npm ci --production=false

# Build JavaScript fuzzers using Jazzer.js
for fuzzer in fuzz_*.js; do
  if [ -f "$fuzzer" ]; then
    echo "Building JavaScript fuzzer: $fuzzer"
    compile_javascript_fuzzer "$SRC/gemini-cli/fuzzers" "$fuzzer" --sync
  fi
done
cd "$SRC/gemini-cli"

# Copy seed corpora
echo "=== Copying Seed Corpora ==="
for dir in seeds/Fuzz*; do
  if [ -d "$dir" ]; then
    name=$(basename "$dir")
    target_name=$(echo "$name" | sed 's/^Fuzz/fuzz_/' | tr '[:upper:]' '[:lower:]' | sed 's/_seed_corpus$//')
    zip -jr "$OUT/${target_name}_seed_corpus.zip" "$dir"
  fi
done

# Copy dictionaries with proper naming
echo "=== Copying Dictionaries ==="
for dict in fuzzers/dictionaries/*.dict; do
  if [ -f "$dict" ]; then
    basename=$(basename "$dict" .dict)
    # Map dictionary to appropriate fuzzers
    case "$basename" in
      json) 
        for target in config mcp_decoder mcp_request mcp_response oauth_token context_file; do
          cp "$dict" "$OUT/fuzz_${target}_parser.dict" 2>/dev/null || true
        done
        ;;
      path)
        for target in symlink_validation path_validation file_system_operations file_path_handler; do
          cp "$dict" "$OUT/fuzz_${target}.dict" 2>/dev/null || true
        done
        ;;
      cli)
        cp "$dict" "$OUT/fuzz_cli_parser.dict"        ;;
      url)
        cp "$dict" "$OUT/fuzz_url_parser.dict"
        ;;
      http)
        cp "$dict" "$OUT/fuzz_http_request_parser.dict"
        ;;
      env)
        cp "$dict" "$OUT/fuzz_env_parser.dict"
        cp "$dict" "$OUT/fuzz_environment_parser.dict"
        ;;
    esac
  fi
done

# Create options files for optimal fuzzing
echo "=== Creating Options Files ==="
for fuzzer in "$OUT"/fuzz_*; do
  if [ -f "$fuzzer" ] && [ ! -f "$fuzzer.options" ]; then
    name=$(basename "$fuzzer")
    cat > "$fuzzer.options" <<EOF
[libfuzzer]
max_len=8192
timeout=60
max_total_time=3600
close_fd_mask=3
detect_leaks=1
use_value_profile=1
shrink=1
reduce_inputs=1
EOF
  fi
done
# Validate build
echo "=== Build Validation ==="
total_fuzzers=$(ls -1 "$OUT"/fuzz_* 2>/dev/null | grep -v -E '\.(dict|options|zip)$' | wc -l)
total_corpora=$(ls -1 "$OUT"/*_seed_corpus.zip 2>/dev/null | wc -l)
total_dicts=$(ls -1 "$OUT"/*.dict 2>/dev/null | wc -l)

echo "Build Summary:"
echo "  Total fuzz targets: $total_fuzzers"
echo "  Total seed corpora: $total_corpora"
echo "  Total dictionaries: $total_dicts"

# List all built fuzzers
echo "Built fuzzers:"
ls -1 "$OUT"/fuzz_* | grep -v -E '\.(dict|options|zip)$' | while read fuzzer; do
  echo "  - $(basename $fuzzer)"
done

# Verify critical security fuzzers
echo "=== Verifying Critical Security Fuzzers ==="
critical_fuzzers="fuzz_symlink_validation fuzz_path_validation fuzz_context_file_parser fuzz_shell_validation"
for fuzzer in $critical_fuzzers; do
  if [ -f "$OUT/$fuzzer" ]; then
    echo "✓ $fuzzer built successfully"
  else
    echo "✗ WARNING: Critical fuzzer $fuzzer not found!"
    exit 1
  fi
done

echo "=== Build completed successfully! ==="
echo "Ready for OSS-Fuzz integration. Focus on Issue #1121 (symlink traversal) and prompt injection vulnerabilities."