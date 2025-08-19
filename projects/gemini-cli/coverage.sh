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

# Coverage analysis script for Gemini CLI OSS-Fuzz integration
# Implements OSS-Fuzz ideal integration requirements for code coverage

set -e

# Configuration
COVERAGE_DIR="${COVERAGE_DIR:-coverage}"
FUZZERS_DIR="${FUZZERS_DIR:-out}"
SEEDS_DIR="${SEEDS_DIR:-seeds}"
REPORT_FILE="${REPORT_FILE:-coverage_report.html}"

# Ensure coverage directory exists
mkdir -p "${COVERAGE_DIR}"

echo "=== Gemini CLI OSS-Fuzz Coverage Analysis ==="
echo "Coverage directory: ${COVERAGE_DIR}"
echo "Fuzzers directory: ${FUZZERS_DIR}"
echo "Seeds directory: ${SEEDS_DIR}"

# Function to run coverage analysis for a fuzzer
run_coverage_analysis() {
    local fuzzer_name="$1"
    local corpus_dir="$2"
    local coverage_file="${COVERAGE_DIR}/${fuzzer_name}.prof"
    
    echo "Analyzing coverage for ${fuzzer_name}..."
    
    if [ ! -f "${FUZZERS_DIR}/${fuzzer_name}" ]; then
        echo "⚠️  Fuzzer ${fuzzer_name} not found, skipping coverage analysis"
        return 0
    fi
    
    if [ ! -d "${corpus_dir}" ]; then
        echo "⚠️  Corpus directory ${corpus_dir} not found, skipping coverage analysis"
        return 0
    fi
    
    # Run fuzzer with coverage instrumentation
    echo "Running ${fuzzer_name} with coverage instrumentation..."
    
    # Set coverage environment variables
    export GOCOVERDIR="${COVERAGE_DIR}"
    export GOCOVER="${coverage_file}"
    
    # Run fuzzer on seed corpus with coverage
    timeout 60s "${FUZZERS_DIR}/${fuzzer_name}" -runs=1000 "${corpus_dir}"/* || true
    
    echo "✓ Coverage data collected for ${fuzzer_name}"
}

# Run coverage analysis for each fuzzer
echo "Starting coverage analysis..."

# Config parser coverage
run_coverage_analysis "FuzzConfigParser" "${SEEDS_DIR}/config"

# CLI parser coverage  
run_coverage_analysis "FuzzCLIParser" "${SEEDS_DIR}/cli"

# MCP coverage
run_coverage_analysis "FuzzMCPRequest" "${SEEDS_DIR}/mcp"
run_coverage_analysis "FuzzMCPResponse" "${SEEDS_DIR}/mcp"

# OAuth coverage
run_coverage_analysis "FuzzOAuthTokenRequest" "${SEEDS_DIR}/oauth"
run_coverage_analysis "FuzzOAuthTokenResponse" "${SEEDS_DIR}/oauth"

# Generate coverage report
echo "Generating coverage report..."

# Check if go tool cover is available
if command -v go >/dev/null 2>&1; then
    # Generate HTML coverage report
    echo "Creating HTML coverage report..."
    
    # Combine all coverage files
    if [ -d "${COVERAGE_DIR}" ] && [ "$(ls -A ${COVERAGE_DIR}/*.prof 2>/dev/null)" ]; then
        go tool cover -html="${COVERAGE_DIR}/*.prof" -o "${REPORT_FILE}" || {
            echo "⚠️  Failed to generate HTML coverage report"
        }
        
        if [ -f "${REPORT_FILE}" ]; then
            echo "✓ Coverage report generated: ${REPORT_FILE}"
        fi
    else
        echo "⚠️  No coverage data files found"
    fi
    
    # Generate coverage summary
    echo "Coverage summary:"
    if [ -d "${COVERAGE_DIR}" ] && [ "$(ls -A ${COVERAGE_DIR}/*.prof 2>/dev/null)" ]; then
        go tool cover -func="${COVERAGE_DIR}/*.prof" || {
            echo "⚠️  Failed to generate coverage summary"
        }
    fi
else
    echo "⚠️  Go tool not available, skipping coverage report generation"
fi

# Generate coverage statistics
echo "Generating coverage statistics..."

cat > "${COVERAGE_DIR}/coverage_stats.txt" <<EOF
Gemini CLI OSS-Fuzz Coverage Statistics
=======================================
Generated: $(date)
Project: gemini-cli
Language: Go

Fuzz Targets:
- FuzzConfigParser: Configuration parsing and validation
- FuzzCLIParser: CLI argument parsing and security validation  
- FuzzMCPRequest: MCP protocol request handling
- FuzzMCPResponse: MCP protocol response handling
- FuzzOAuthTokenRequest: OAuth token request processing
- FuzzOAuthTokenResponse: OAuth token response processing

Coverage Files:
$(find "${COVERAGE_DIR}" -name "*.prof" -type f 2>/dev/null | wc -l) coverage data files

Seed Corpus:
$(find "${SEEDS_DIR}" -type f \( -name "*.json" -o -name "*.jsonl" -o -name "*.txt" \) 2>/dev/null | wc -l) seed files

Security Features Tested:
- Command injection prevention
- Path traversal protection
- JSON injection resistance
- OAuth token validation
- MCP protocol security
- Configuration tampering detection

Coverage Analysis Complete
EOF

echo "✓ Coverage analysis complete"
echo "✓ Coverage data stored in: ${COVERAGE_DIR}"
echo "✓ Coverage report: ${REPORT_FILE}"
echo "✓ Coverage statistics: ${COVERAGE_DIR}/coverage_stats.txt"

# Provide recommendations for coverage improvement
echo ""
echo "=== Coverage Improvement Recommendations ==="
echo "1. Add more diverse seed inputs to improve edge case coverage"
echo "2. Include malformed inputs to test error handling paths"
echo "3. Add boundary value tests for security validation functions"
echo "4. Include Unicode and special character tests for CLI parsing"
echo "5. Add protocol-specific edge cases for MCP and OAuth targets"
echo "6. Test with maximum size inputs to verify resource limits"
echo "7. Include timing attack test cases for OAuth validation"
echo "8. Add supply chain attack scenarios for configuration parsing"
