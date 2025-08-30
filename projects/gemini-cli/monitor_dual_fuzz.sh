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

# Dual-Language Fuzzing Monitor
# Monitors the status of both Go and JavaScript fuzzers
#
# Usage: ./monitor_dual_fuzz.sh [refresh_interval_seconds]
#
# Examples:
#   ./monitor_dual_fuzz.sh 5     # Update every 5 seconds
#   ./monitor_dual_fuzz.sh       # Update every 10 seconds (default)

REFRESH="${1:-10}"

echo "=== DUAL-LANGUAGE FUZZING MONITOR ==="
echo "Monitoring both Go and JavaScript fuzzers..."
echo "Refresh interval: ${REFRESH}s"
echo "Press Ctrl+C to stop monitoring"
echo ""

while true; do
    clear
    echo "=== DUAL-LANGUAGE FUZZING MONITOR ==="
    echo "Timestamp: $(date)"
    echo ""

    # System Resources
    echo "📊 SYSTEM RESOURCES:"
    if command -v free >/dev/null 2>&1; then
        echo "Memory: $(free -h | grep '^Mem:' | awk '{print $3 "/" $2}')"
    fi
    if command -v df >/dev/null 2>&1; then
        echo "Disk: $(df -h . | tail -1 | awk '{print $3 "/" $2 " (" $5 " used)"}')"
    fi
    echo ""

    # Go Fuzzer Status
    echo "🐹 GO FUZZERS (Native Go Fuzzing):"
    GO_PROCESSES=$(ps aux | grep -E "Fuzz[A-Z]" | grep -v grep | wc -l)
    echo "Active Go fuzzers: $GO_PROCESSES"

    if [ $GO_PROCESSES -gt 0 ]; then
        echo "Running Go fuzz targets:"
        ps aux | grep -E "Fuzz[A-Z]" | grep -v grep | awk '{print "  - " $NF}' | sort
    else
        echo "⚠️  No Go fuzzers currently running"
    fi
    echo ""

    # JavaScript Fuzzer Status
    echo "🌐 JAVASCRIPT FUZZERS (Jazzer.js):"
    JS_PROCESSES=$(ps aux | grep -E "fuzz_[a-z]" | grep -v grep | wc -l)
    echo "Active JavaScript fuzzers: $JS_PROCESSES"

    if [ $JS_PROCESSES -gt 0 ]; then
        echo "Running JavaScript fuzz targets:"
        ps aux | grep -E "fuzz_[a-z]" | grep -v grep | awk '{print "  - " $NF}' | sort
    else
        echo "⚠️  No JavaScript fuzzers currently running"
    fi
    echo ""

    # Total Fuzzing Activity
    TOTAL_PROCESSES=$((GO_PROCESSES + JS_PROCESSES))
    echo "🎯 TOTAL ACTIVITY:"
    echo "Combined fuzzers: $TOTAL_PROCESSES"
    echo ""

    # Coverage Status (if available)
    echo "📈 COVERAGE STATUS:"
    if [ -d "corpus" ]; then
        CORPUS_SIZE=$(find corpus -type f 2>/dev/null | wc -l)
        echo "Corpus files: $CORPUS_SIZE"
    fi

    if [ -d "crashes" ]; then
        CRASH_COUNT=$(find crashes -type f 2>/dev/null | wc -l)
        if [ "$CRASH_COUNT" -gt 0 ]; then
            echo "⚠️  Crashes found: $CRASH_COUNT"
        else
            echo "✅ No crashes detected"
        fi
    fi
    echo ""

    # Recent Activity
    echo "🔥 RECENT ACTIVITY:"
    echo "Recent log entries:"
    if [ -f "fuzzing.log" ]; then
        tail -5 fuzzing.log 2>/dev/null || echo "No recent log entries"
    else
        echo "No fuzzing log available"
    fi
    echo ""

    # Performance Metrics
    echo "⚡ PERFORMANCE METRICS:"
    CPU_USAGE=$(ps aux | grep -E "(Fuzz|fuzz_)" | grep -v grep | awk '{sum+=$3} END {print sum "%"}' 2>/dev/null || echo "N/A")
    echo "CPU usage by fuzzers: $CPU_USAGE"

    if command -v top >/dev/null 2>&1; then
        echo "Top processes by CPU:"
        ps aux | grep -E "(Fuzz|fuzz_)" | grep -v grep | sort -nr -k3 | head -3 | awk '{print "  - " $NF ": " $3 "% CPU"}' 2>/dev/null || echo "  No fuzzer processes found"
    fi
    echo ""

    # Recommendations
    echo "💡 RECOMMENDATIONS:"
    if [ $TOTAL_PROCESSES -eq 0 ]; then
        echo "  - Start fuzzing with: ./run_dual_fuzz.sh"
    elif [ $GO_PROCESSES -eq 0 ]; then
        echo "  - Start Go fuzzers for better coverage"
    elif [ $JS_PROCESSES -eq 0 ]; then
        echo "  - Start JavaScript fuzzers for runtime testing"
    else
        echo "  - Fuzzing is running optimally!"
        echo "  - Monitor for crashes in ./crashes/"
        echo "  - Check coverage reports periodically"
    fi

    sleep $REFRESH
done
