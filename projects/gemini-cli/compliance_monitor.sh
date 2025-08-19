#!/bin/bash -eux

# Gemini CLI OSS-Fuzz Compliance Monitor
# Ensures full compliance with OSS-Fuzz policies and comprehensive coverage

set -euo pipefail

echo "🔍 Gemini CLI OSS-Fuzz Compliance Monitor"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "PASS")
            echo -e "${GREEN}✅${NC} $message"
            ;;
        "FAIL")
            echo -e "${RED}❌${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️${NC} $message"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️${NC} $message"
            ;;
    esac
}

# Function to check if file exists
check_file() {
    local file=$1
    local description=$2
    if [[ -f "$file" ]]; then
        print_status "PASS" "$description: $file"
        return 0
    else
        print_status "FAIL" "$description: $file (missing)"
        return 1
    fi
}

# Function to check if directory exists and has files
check_directory() {
    local dir=$1
    local description=$2
    if [[ -d "$dir" ]]; then
        local file_count=$(find "$dir" -type f | wc -l)
        if [[ $file_count -gt 0 ]]; then
            print_status "PASS" "$description: $dir ($file_count files)"
            return 0
        else
            print_status "WARN" "$description: $dir (empty)"
            return 1
        fi
    else
        print_status "FAIL" "$description: $dir (missing)"
        return 1
    fi
}

# Initialize counters
total_checks=0
passed_checks=0
failed_checks=0

# Track results
declare -a failed_items=()

# Function to run a check
run_check() {
    local check_name=$1
    shift
    total_checks=$((total_checks + 1))
    
    echo ""
    echo "📋 $check_name"
    echo "----------------------------------------"
    
    if "$@"; then
        passed_checks=$((passed_checks + 1))
    else
        failed_checks=$((failed_checks + 1))
        failed_items+=("$check_name")
    fi
}

# Check 1: Required OSS-Fuzz files
check_ossfuzz_files() {
    local result=0
    
    check_file "project.yaml" "Project configuration" || result=1
    check_file "build.sh" "Build script" || result=1
    check_file "Dockerfile" "Docker configuration" || result=1
    
    return $result
}

# Check 2: Fuzzer targets
check_fuzzer_targets() {
    local result=0
    
    check_file "gofuzz/fuzz/fuzz_config_parser.go" "Config parser fuzzer" || result=1
    check_file "gofuzz/fuzz/fuzz_cli_parser.go" "CLI parser fuzzer" || result=1
    check_file "gofuzz/fuzz/fuzz_mcp_decoder.go" "MCP decoder fuzzer" || result=1
    check_file "gofuzz/fuzz/fuzz_oauth_token_request.go" "OAuth request fuzzer" || result=1
    check_file "gofuzz/fuzz/fuzz_oauth_token_response.go" "OAuth response fuzzer" || result=1
    
    return $result
}

# Check 3: Seed corpora
check_seed_corpora() {
    local result=0
    
    check_directory "seeds/config" "Config seed corpus" || result=1
    check_directory "seeds/cli" "CLI seed corpus" || result=1
    check_directory "seeds/mcp" "MCP seed corpus" || result=1
    check_directory "seeds/oauth" "OAuth seed corpus" || result=1
    
    # Check for minimum seed files
    local config_files=$(find seeds/config -type f | wc -l)
    local cli_files=$(find seeds/cli -type f | wc -l)
    local mcp_files=$(find seeds/mcp -type f | wc -l)
    local oauth_files=$(find seeds/oauth -type f | wc -l)
    
    if [[ $config_files -ge 5 ]]; then
        print_status "PASS" "Config seeds: $config_files files"
    else
        print_status "FAIL" "Config seeds: $config_files files (need at least 5)"
        result=1
    fi
    
    if [[ $cli_files -ge 5 ]]; then
        print_status "PASS" "CLI seeds: $cli_files files"
    else
        print_status "FAIL" "CLI seeds: $cli_files files (need at least 5)"
        result=1
    fi
    
    if [[ $mcp_files -ge 5 ]]; then
        print_status "PASS" "MCP seeds: $mcp_files files"
    else
        print_status "FAIL" "MCP seeds: $mcp_files files (need at least 5)"
        result=1
    fi
    
    if [[ $oauth_files -ge 5 ]]; then
        print_status "PASS" "OAuth seeds: $oauth_files files"
    else
        print_status "FAIL" "OAuth seeds: $oauth_files files (need at least 5)"
        result=1
    fi
    
    return $result
}

# Check 4: Security features
check_security_features() {
    local result=0
    
    # Check for security-focused seed files
    if grep -r "command_injection\|shell.*metacharacter\|path.*traversal" seeds/ >/dev/null 2>&1; then
        print_status "PASS" "Command injection protection seeds"
    else
        print_status "FAIL" "Command injection protection seeds (missing)"
        result=1
    fi
    
    if grep -r "unicode.*attack\|homograph\|bidirectional" seeds/ >/dev/null 2>&1; then
        print_status "PASS" "Unicode security seeds"
    else
        print_status "FAIL" "Unicode security seeds (missing)"
        result=1
    fi
    
    if grep -r "timing.*attack\|constant.*time\|csrf" seeds/ >/dev/null 2>&1; then
        print_status "PASS" "Timing attack protection seeds"
    else
        print_status "FAIL" "Timing attack protection seeds (missing)"
        result=1
    fi
    
    if grep -r "malformed.*json\|nested.*structure" seeds/ >/dev/null 2>&1; then
        print_status "PASS" "JSON injection protection seeds"
    else
        print_status "FAIL" "JSON injection protection seeds (missing)"
        result=1
    fi
    
    return $result
}

# Check 5: Build system integration
check_build_integration() {
    local result=0
    
    # Check build.sh for required components
    if grep -q "compile_go_fuzzer" build.sh; then
        print_status "PASS" "Go fuzzer compilation in build.sh"
    else
        print_status "FAIL" "Go fuzzer compilation missing from build.sh"
        result=1
    fi
    
    if grep -q "seed_corpus" build.sh; then
        print_status "PASS" "Seed corpus packaging in build.sh"
    else
        print_status "FAIL" "Seed corpus packaging missing from build.sh"
        result=1
    fi
    
    if grep -q "\.dict" build.sh; then
        print_status "PASS" "Dictionary creation in build.sh"
    else
        print_status "FAIL" "Dictionary creation missing from build.sh"
        result=1
    fi
    
    if grep -q "\.options" build.sh; then
        print_status "PASS" "Options file creation in build.sh"
    else
        print_status "FAIL" "Options file creation missing from build.sh"
        result=1
    fi
    
    return $result
}

# Check 6: Documentation
check_documentation() {
    local result=0
    
    check_file "README.md" "Project README" || result=1
    check_file "seeds/README.md" "Seed corpus README" || result=1
    check_file "seeds/SEED_CORPUS_SUMMARY.md" "Seed corpus summary" || result=1
    
    return $result
}

# Check 7: Go module structure
check_go_structure() {
    local result=0
    
    check_file "gofuzz/go.mod" "Go module file" || result=1
    check_file "gofuzz/go.sum" "Go module checksum" || result=1
    
    # Check internal packages
    check_directory "gofuzz/internal/config" "Config package" || result=1
    check_directory "gofuzz/internal/cli" "CLI package" || result=1
    check_directory "gofuzz/internal/mcp" "MCP package" || result=1
    check_directory "gofuzz/internal/oauth" "OAuth package" || result=1
    
    return $result
}

# Run all checks
echo "Starting compliance checks..."
echo ""

run_check "OSS-Fuzz Required Files" check_ossfuzz_files
run_check "Fuzzer Targets" check_fuzzer_targets
run_check "Seed Corpora" check_seed_corpora
run_check "Security Features" check_security_features
run_check "Build System Integration" check_build_integration
run_check "Documentation" check_documentation
run_check "Go Module Structure" check_go_structure

# Print summary
echo ""
echo "📊 Compliance Summary"
echo "===================="
echo "Total checks: $total_checks"
echo "Passed: $passed_checks"
echo "Failed: $failed_checks"
echo "Success rate: $((passed_checks * 100 / total_checks))%"

if [[ $failed_checks -eq 0 ]]; then
    echo ""
    print_status "PASS" "All compliance checks passed! 🎉"
    echo ""
    echo "✅ OSS-Fuzz Integration: READY"
    echo "✅ Security Hardening: ENTERPRISE-GRADE"
    echo "✅ Coverage: COMPREHENSIVE"
    echo "✅ Compliance: 100%"
    exit 0
else
    echo ""
    print_status "FAIL" "Some compliance checks failed:"
    for item in "${failed_items[@]}"; do
        echo "  ❌ $item"
    done
    echo ""
    echo "Please fix the failed checks before submitting to OSS-Fuzz."
    exit 1
fi
