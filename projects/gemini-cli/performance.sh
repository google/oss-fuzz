#!/bin/bash -eux
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
################################################################################

# Performance monitoring script for Gemini CLI OSS-Fuzz integration
# Implements OSS-Fuzz ideal integration requirements for performance analysis

set -e

# Configuration
PERF_DIR="${PERF_DIR:-performance}"
FUZZERS_DIR="${FUZZERS_DIR:-out}"
SEEDS_DIR="${SEEDS_DIR:-seeds}"
REPORT_FILE="${REPORT_FILE:-performance_report.txt}"
MAX_RUNTIME="${MAX_RUNTIME:-60}"
MAX_MEMORY="${MAX_MEMORY:-2048}"

# Ensure performance directory exists
mkdir -p "${PERF_DIR}"

echo "=== Gemini CLI OSS-Fuzz Performance Analysis ==="
echo "Performance directory: ${PERF_DIR}"
echo "Fuzzers directory: ${FUZZERS_DIR}"
echo "Seeds directory: ${SEEDS_DIR}"
echo "Max runtime: ${MAX_RUNTIME}s"
echo "Max memory: ${MAX_MEMORY}MB"

# Function to measure performance for a fuzzer
measure_performance() {
    local fuzzer_name="$1"
    local corpus_dir="$2"
    local perf_file="${PERF_DIR}/${fuzzer_name}_performance.txt"
    
    echo "Measuring performance for ${fuzzer_name}..."
    
    if [ ! -f "${FUZZERS_DIR}/${fuzzer_name}" ]; then
        echo "⚠️  Fuzzer ${fuzzer_name} not found, skipping performance analysis"
        return 0
    fi
    
    if [ ! -d "${corpus_dir}" ]; then
        echo "⚠️  Corpus directory ${corpus_dir} not found, skipping performance analysis"
        return 0
    fi
    
    # Run performance measurement
    echo "Running ${fuzzer_name} performance test..."
    
    # Measure execution time and memory usage
    {
        echo "Performance Test Results for ${fuzzer_name}"
        echo "=========================================="
        echo "Test started: $(date)"
        echo ""
        
        # Run with time measurement
        echo "Execution time measurement:"
        /usr/bin/time -v timeout "${MAX_RUNTIME}" "${FUZZERS_DIR}/${fuzzer_name}" -runs=1000 "${corpus_dir}"/* 2>&1 || true
        
        echo ""
        echo "Memory usage analysis:"
        
        # Monitor memory usage during execution
        timeout "${MAX_RUNTIME}" bash -c "
            ${FUZZERS_DIR}/${fuzzer_name} -runs=1000 ${corpus_dir}/* &
            FUZZER_PID=\$!
            
            # Monitor memory usage
            while kill -0 \$FUZZER_PID 2>/dev/null; do
                if command -v ps >/dev/null 2>&1; then
                    MEMORY=\$(ps -o rss= -p \$FUZZER_PID 2>/dev/null | tr -d ' ')
                    if [ -n \"\$MEMORY\" ]; then
                        echo \"Memory usage: \${MEMORY}KB\"
                        if [ \$MEMORY -gt ${MAX_MEMORY} ]; then
                            echo \"⚠️  Memory usage exceeded limit (\${MEMORY}KB > ${MAX_MEMORY}KB)\"
                        fi
                    fi
                fi
                sleep 5
            done
        " || true
        
        echo ""
        echo "Test completed: $(date)"
        
    } > "${perf_file}" 2>&1
    
    echo "✓ Performance data collected for ${fuzzer_name}"
}

# Function to analyze performance bottlenecks
analyze_bottlenecks() {
    local fuzzer_name="$1"
    local perf_file="${PERF_DIR}/${fuzzer_name}_performance.txt"
    
    if [ ! -f "${perf_file}" ]; then
        return 0
    fi
    
    echo "Analyzing performance bottlenecks for ${fuzzer_name}..."
    
    # Extract key metrics
    local exec_time=$(grep "Elapsed (wall clock) time" "${perf_file}" | awk '{print $8}' || echo "N/A")
    local max_memory=$(grep "Maximum resident set size" "${perf_file}" | awk '{print $6}' || echo "N/A")
    local memory_warnings=$(grep -c "Memory usage exceeded limit" "${perf_file}" || echo "0")
    
    # Generate bottleneck analysis
    {
        echo "Performance Bottleneck Analysis for ${fuzzer_name}"
        echo "================================================"
        echo "Execution time: ${exec_time}"
        echo "Maximum memory: ${max_memory}KB"
        echo "Memory limit violations: ${memory_warnings}"
        echo ""
        
        # Identify potential issues
        if [ "${memory_warnings}" -gt 0 ]; then
            echo "❌ PERFORMANCE ISSUE: Memory usage exceeded limits"
            echo "   - Consider reducing input size limits"
            echo "   - Optimize memory allocation patterns"
            echo "   - Review data structure efficiency"
        fi
        
        if [ "${exec_time}" != "N/A" ]; then
            # Convert to seconds for comparison
            local time_seconds=$(echo "${exec_time}" | sed 's/:/ /g' | awk '{print $1*60 + $2}')
            if [ "${time_seconds}" -gt "${MAX_RUNTIME}" ]; then
                echo "❌ PERFORMANCE ISSUE: Execution time exceeded limit"
                echo "   - Consider optimizing algorithm complexity"
                echo "   - Review input processing efficiency"
                echo "   - Check for unnecessary computations"
            fi
        fi
        
        echo ""
        echo "Recommendations:"
        echo "1. Monitor memory allocation patterns"
        echo "2. Optimize string processing operations"
        echo "3. Review security validation efficiency"
        echo "4. Consider caching frequently accessed data"
        echo "5. Profile hot code paths for optimization"
        
    } > "${PERF_DIR}/${fuzzer_name}_bottlenecks.txt"
    
    echo "✓ Bottleneck analysis completed for ${fuzzer_name}"
}

# Run performance analysis for each fuzzer
echo "Starting performance analysis..."

# Config parser performance
measure_performance "FuzzConfigParser" "${SEEDS_DIR}/config"
analyze_bottlenecks "FuzzConfigParser"

# CLI parser performance
measure_performance "FuzzCLIParser" "${SEEDS_DIR}/cli"
analyze_bottlenecks "FuzzCLIParser"

# MCP performance
measure_performance "FuzzMCPRequest" "${SEEDS_DIR}/mcp"
analyze_bottlenecks "FuzzMCPRequest"
measure_performance "FuzzMCPResponse" "${SEEDS_DIR}/mcp"
analyze_bottlenecks "FuzzMCPResponse"

# OAuth performance
measure_performance "FuzzOAuthTokenRequest" "${SEEDS_DIR}/oauth"
analyze_bottlenecks "FuzzOAuthTokenRequest"
measure_performance "FuzzOAuthTokenResponse" "${SEEDS_DIR}/oauth"
analyze_bottlenecks "FuzzOAuthTokenResponse"

# Generate comprehensive performance report
echo "Generating comprehensive performance report..."

cat > "${REPORT_FILE}" <<EOF
Gemini CLI OSS-Fuzz Performance Report
======================================
Generated: $(date)
Project: gemini-cli
Language: Go

Performance Configuration:
- Max runtime per fuzzer: ${MAX_RUNTIME} seconds
- Max memory per fuzzer: ${MAX_MEMORY} MB
- Performance data directory: ${PERF_DIR}

Fuzz Target Performance Summary:
EOF

# Add performance summary for each fuzzer
for fuzzer in FuzzConfigParser FuzzCLIParser FuzzMCPRequest FuzzMCPResponse FuzzOAuthTokenRequest FuzzOAuthTokenResponse; do
    perf_file="${PERF_DIR}/${fuzzer}_performance.txt"
    bottleneck_file="${PERF_DIR}/${fuzzer}_bottlenecks.txt"
    
    if [ -f "${perf_file}" ]; then
        echo "" >> "${REPORT_FILE}"
        echo "${fuzzer}:" >> "${REPORT_FILE}"
        echo "  Performance data: ${perf_file}" >> "${REPORT_FILE}"
        
        if [ -f "${bottleneck_file}" ]; then
            echo "  Bottleneck analysis: ${bottleneck_file}" >> "${REPORT_FILE}"
        fi
        
        # Extract key metrics
        exec_time=$(grep "Elapsed (wall clock) time" "${perf_file}" | awk '{print $8}' || echo "N/A")
        max_memory=$(grep "Maximum resident set size" "${perf_file}" | awk '{print $6}' || echo "N/A")
        
        echo "  Execution time: ${exec_time}" >> "${REPORT_FILE}"
        echo "  Max memory: ${max_memory}KB" >> "${REPORT_FILE}"
    fi
done

cat >> "${REPORT_FILE}" <<EOF

Performance Recommendations:
1. Monitor memory usage patterns during fuzzing
2. Optimize input processing for large files
3. Review security validation algorithm efficiency
4. Consider parallel processing for independent operations
5. Profile hot code paths for optimization opportunities
6. Implement early termination for invalid inputs
7. Use efficient data structures for large datasets
8. Consider caching for repeated operations

Performance Analysis Complete
EOF

echo "✓ Performance analysis complete"
echo "✓ Performance data stored in: ${PERF_DIR}"
echo "✓ Performance report: ${REPORT_FILE}"

# Provide performance optimization guidance
echo ""
echo "=== Performance Optimization Guidance ==="
echo "1. Use efficient string processing (avoid excessive allocations)"
echo "2. Implement early validation to reject invalid inputs quickly"
echo "3. Consider using object pools for frequently allocated structures"
echo "4. Profile memory usage patterns and optimize allocations"
echo "5. Use appropriate data structures for the input size"
echo "6. Implement timeout mechanisms to prevent infinite loops"
echo "7. Consider parallel processing for independent validation steps"
echo "8. Monitor and optimize I/O operations if present"
