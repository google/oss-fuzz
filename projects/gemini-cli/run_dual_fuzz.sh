#!/bin/bash
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

# Unified Dual-Language Fuzzing Runner
# Runs both Go and JavaScript fuzzers in parallel for comprehensive testing
#
# Usage: ./run_dual_fuzz.sh [duration_seconds] [jobs_per_language]
#
# Examples:
#   ./run_dual_fuzz.sh 300 2    # Run for 5 minutes, 2 fuzzers per language
#   ./run_dual_fuzz.sh 60 1     # Run for 1 minute, 1 fuzzer per language
#   ./run_dual_fuzz.sh          # Run indefinitely, 1 fuzzer per language

DURATION="${1:-0}"  # 0 = run indefinitely
JOBS="${2:-1}"      # Number of parallel fuzzers per language

echo "=== DUAL-LANGUAGE FUZZING RUNNER ==="
echo "Duration: $DURATION seconds (0 = indefinite)"
echo "Jobs per language: $JOBS"
echo "Total parallel fuzzers: $((JOBS * 2))"
echo ""

# Go fuzz targets (native Go fuzzing)
GO_TARGETS=(
    "FuzzConfigParser"
    "FuzzCLIParser"
    "FuzzMCPDecoder"
    "FuzzMCPRequest"
    "FuzzMCPResponse"
    "FuzzOAuthTokenRequest"
    "FuzzOAuthTokenResponse"
    "FuzzFileSystemOperations"
    "FuzzURLParser"
    "FuzzCryptoOperations"
    "FuzzEnvironmentParser"
    "FuzzInputSanitizer"
    "FuzzSlashCommands"
    "FuzzToolInvocation"
    "FuzzTypeScriptBridge"
    "FuzzSymlinkValidation"
    "FuzzShellValidation"
    "FuzzContextFileParser"
    "FuzzPathValidation"
)

# JavaScript fuzz targets (Jazzer.js)
JS_TARGETS=(
    "fuzz_config_parser"
    "fuzz_cli_parser"
    "fuzz_env_parser"
    "fuzz_file_path_handler"
    "fuzz_http_request_parser"
    "fuzz_mcp_request"
    "fuzz_mcp_response"
    "fuzz_oauth_token_request"
    "fuzz_oauth_token_response"
    "fuzz_response_parser"
    "fuzz_url_parser"
)

# Function to run Go fuzzers
run_go_fuzzers() {
    echo "[GO] Starting $JOBS Go fuzzers..."

    for ((i=0; i<JOBS && i<${#GO_TARGETS[@]}; i++)); do
        target="${GO_TARGETS[$i]}"
        if [ -f "$target" ]; then
            echo "[GO] Running $target..."
            if [ "$DURATION" -gt 0 ]; then
                timeout "${DURATION}s" ./"$target" -jobs=1 &
            else
                ./"$target" -jobs=1 &
            fi
        else
            echo "[GO] Warning: $target not found"
        fi
    done
}

# Function to run JavaScript fuzzers
run_js_fuzzers() {
    echo "[JS] Starting $JOBS JavaScript fuzzers..."

    for ((i=0; i<JOBS && i<${#JS_TARGETS[@]}; i++)); do
        target="${JS_TARGETS[$i]}"
        if [ -f "$target" ]; then
            echo "[JS] Running $target..."
            if [ "$DURATION" -gt 0 ]; then
                timeout "${DURATION}s" ./"$target" &
            else
                ./"$target" &
            fi
        else
            echo "[JS] Warning: $target not found"
        fi
    done
}

# Function to show progress
show_progress() {
    echo ""
    echo "=== DUAL-LANGUAGE FUZZING IN PROGRESS ==="
    echo "[GO] Running Go fuzz targets (native fuzzing)"
    echo "[JS] Running JavaScript fuzz targets (Jazzer.js)"
    echo ""
    echo "Active processes:"
    ps aux | grep -E "(Fuzz|fuzz_)" | grep -v grep || true
    echo ""
}

# Main execution
echo "Starting dual-language fuzzing..."

# Start Go fuzzers in background
run_go_fuzzers

# Start JavaScript fuzzers in background
run_js_fuzzers

# Show initial progress
sleep 2
show_progress

# Monitor progress if running for a limited time
if [ "$DURATION" -gt 0 ]; then
    remaining=$DURATION
    while [ $remaining -gt 0 ]; do
        sleep 30
        remaining=$((remaining - 30))
        echo "[PROGRESS] Time remaining: ${remaining}s"
        show_progress
    done

    echo ""
    echo "=== FUZZING COMPLETED ==="
    echo "Stopping all fuzzers..."

    # Stop all fuzzing processes
    pkill -f "Fuzz" || true
    pkill -f "fuzz_" || true

    echo "✅ Dual-language fuzzing session completed"
else
    echo "=== INDEFINITE FUZZING MODE ==="
    echo "Fuzzers are running continuously. Press Ctrl+C to stop."
    echo "Use 'ps aux | grep -E \"(Fuzz|fuzz_)\"' to see active fuzzers"

    # Monitor indefinitely
    while true; do
        sleep 60
        show_progress
    done
fi
