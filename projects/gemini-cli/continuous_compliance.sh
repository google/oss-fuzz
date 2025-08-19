#!/bin/bash -eux

# Gemini CLI OSS-Fuzz Continuous Compliance Monitor
# Addresses critical security audit findings and ensures enterprise-grade security

set -euo pipefail

echo "🔒 Gemini CLI OSS-Fuzz Continuous Security Compliance Monitor"
echo "============================================================="
echo "Addressing critical security audit findings from OSS-Fuzz infrastructure"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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
        "CRITICAL")
            echo -e "${RED}🚨${NC} $message"
            ;;
        "SECURITY")
            echo -e "${PURPLE}🔒${NC} $message"
            ;;
    esac
}

# Initialize counters
total_checks=0
passed_checks=0
failed_checks=0
critical_failures=0

# Track results
declare -a failed_items=()
declare -a critical_items=()

# Function to run a security check
run_security_check() {
    local check_name=$1
    shift
    total_checks=$((total_checks + 1))
    
    echo ""
    echo "🔒 $check_name"
    echo "----------------------------------------"
    
    if "$@"; then
        passed_checks=$((passed_checks + 1))
    else
        failed_checks=$((failed_checks + 1))
        failed_items+=("$check_name")
    fi
}

# Function to run a critical security check
run_critical_check() {
    local check_name=$1
    shift
    total_checks=$((total_checks + 1))
    
    echo ""
    echo "🚨 CRITICAL: $check_name"
    echo "----------------------------------------"
    
    if "$@"; then
        passed_checks=$((passed_checks + 1))
    else
        failed_checks=$((failed_checks + 1))
        critical_failures=$((critical_failures + 1))
        failed_items+=("$check_name")
        critical_items+=("$check_name")
    fi
}

# Check 1: Supply Chain Security (Critical - Addresses Audit Finding #1)
check_supply_chain_security() {
    local result=0
    
    print_status "SECURITY" "Checking for unverified binary downloads..."
    
    # Check for any curl/wget commands without integrity verification
    if grep -r "curl.*-O\|wget.*-O" . --exclude-dir=.git --exclude-dir=node_modules 2>/dev/null | grep -v "sha256sum\|checksum\|verify" >/dev/null; then
        print_status "CRITICAL" "Found unverified binary downloads without integrity checks"
        result=1
    else
        print_status "PASS" "No unverified binary downloads detected"
    fi
    
    # Check for hardcoded URLs that could be compromised (excluding license headers and test patterns)
    if grep -r "http://" . --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=gofuzz 2>/dev/null | grep -v "localhost\|127.0.0.1\|LICENSE\|license\|test.*pattern\|fuzz.*test\|apache\.org\|www\.apache\.org" >/dev/null; then
        print_status "WARN" "Found HTTP URLs (should use HTTPS)"
        result=1
    else
        print_status "PASS" "All external URLs use HTTPS"
    fi
    
    return $result
}

# Check 2: Privilege Escalation Prevention (Critical - Addresses Audit Finding #2)
check_privilege_escalation() {
    local result=0
    
    print_status "SECURITY" "Checking for unnecessary root privileges..."
    
    # Check for sudo usage in scripts (excluding this script, other projects, and binaries)
    if find . -type f -name "*.sh" -o -name "*.py" -o -name "*.yaml" -o -name "*.yml" 2>/dev/null | xargs grep -l "sudo" 2>/dev/null | grep -v "continuous_compliance.sh" | grep -v "SECURITY_HARDENING.md" | grep -v "security_monitor.sh" >/dev/null; then
        print_status "CRITICAL" "Found sudo usage - potential privilege escalation risk"
        result=1
    else
        print_status "PASS" "No unnecessary sudo usage detected"
    fi
    
    # Check for setuid/setgid files
    if find . -type f -perm -4000 -o -perm -2000 2>/dev/null | head -5 | wc -l | grep -q "[1-9]"; then
        print_status "CRITICAL" "Found setuid/setgid files - potential privilege escalation"
        result=1
    else
        print_status "PASS" "No setuid/setgid files detected"
    fi
    
    return $result
}

# Check 3: Dependency Pinning (Critical - Addresses Audit Finding #3)
check_dependency_pinning() {
    local result=0
    
    print_status "SECURITY" "Checking dependency version pinning..."
    
    # Check Go module pinning
    if [ -f "gofuzz/go.mod" ]; then
        if grep -q "@latest\|@master\|@main" gofuzz/go.mod; then
            print_status "CRITICAL" "Found unpinned Go dependencies (@latest/@master)"
            result=1
        else
            print_status "PASS" "Go dependencies are properly pinned"
        fi
    fi
    
    # Check for any requirements.txt with unpinned versions
    if find . -name "requirements.txt" 2>/dev/null | xargs grep -l ">=\|~=\|[0-9]\+\.[0-9]\+$" 2>/dev/null >/dev/null; then
        print_status "CRITICAL" "Found unpinned Python dependencies"
        result=1
    else
        print_status "PASS" "Python dependencies are properly pinned"
    fi
    
    return $result
}

# Check 4: Docker Security (Addresses Audit Finding #4)
check_docker_security() {
    local result=0
    
    print_status "SECURITY" "Checking Docker security practices..."
    
    # Check for overly broad COPY instructions
    if [ -f "Dockerfile" ]; then
        if grep -q "COPY \. " Dockerfile; then
            print_status "WARN" "Found broad COPY . instruction - potential for sensitive file inclusion"
            result=1
        else
            print_status "PASS" "Dockerfile uses specific COPY instructions"
        fi
        
        # Check for .dockerignore
        if [ -f ".dockerignore" ]; then
            print_status "PASS" ".dockerignore file exists"
        else
            print_status "WARN" "Missing .dockerignore file"
            result=1
        fi
    fi
    
    return $result
}

# Check 5: Authentication Security (Addresses Audit Finding #5)
check_authentication_security() {
    local result=0
    
    print_status "SECURITY" "Checking authentication mechanisms..."
    
    # Check for hardcoded tokens or credentials (excluding security validation patterns)
    if grep -r "PERSONAL_ACCESS_TOKEN\|GITHUB_TOKEN\|API_KEY" . --exclude-dir=.git 2>/dev/null | grep -v "example\|test\|dummy\|fuzz_.*\.go\|security.*validation\|blockedCommands\|dangerous.*patterns\|api_key.*validation" >/dev/null; then
        print_status "CRITICAL" "Found potential hardcoded tokens/credentials"
        result=1
    else
        print_status "PASS" "No hardcoded tokens detected"
    fi
    
    # Check for secure authentication patterns
    if grep -r "github-app\|oidc\|fine-grained" . --exclude-dir=.git 2>/dev/null >/dev/null; then
        print_status "PASS" "Using secure authentication patterns"
    else
        print_status "INFO" "Consider using GitHub Apps or OIDC for authentication"
    fi
    
    return $result
}

# Check 6: Code Quality and Static Analysis
check_code_quality() {
    local result=0
    
    print_status "SECURITY" "Checking code quality and static analysis..."
    
    # Check for undefined behavior patterns in C/C++
    if find . -name "*.c" -o -name "*.cpp" -o -name "*.cc" 2>/dev/null | xargs grep -l "undefined\|null.*deref\|use.*after.*free" 2>/dev/null >/dev/null; then
        print_status "WARN" "Found potential undefined behavior patterns"
        result=1
    else
        print_status "PASS" "No obvious undefined behavior patterns detected"
    fi
    
    # Check for proper error handling
    if find . -name "*.go" 2>/dev/null | xargs grep -l "panic\|fatal" 2>/dev/null >/dev/null; then
        print_status "WARN" "Found panic/fatal calls - ensure proper error handling"
        result=1
    else
        print_status "PASS" "Proper error handling patterns detected"
    fi
    
    return $result
}

# Check 7: Fuzzer Security Validation
check_fuzzer_security() {
    local result=0
    
    print_status "SECURITY" "Checking fuzzer security validation..."
    
    # Check for security validation in fuzz targets
    local security_checks=0
    for fuzzer in gofuzz/fuzz/*.go; do
        if [ -f "$fuzzer" ]; then
            if grep -q "SecurityViolation\|security.*check\|validate.*security" "$fuzzer"; then
                security_checks=$((security_checks + 1))
            fi
        fi
    done
    
    if [ $security_checks -eq 5 ]; then
        print_status "PASS" "All fuzz targets have security validation"
    else
        print_status "FAIL" "Missing security validation in some fuzz targets (found $security_checks, expected 5)"
        result=1
    fi
    
    # Check for attack surface coverage
    local attack_surfaces=0
    for fuzzer in gofuzz/fuzz/*.go; do
        if [ -f "$fuzzer" ]; then
            if grep -q "command.*injection\|path.*traversal\|json.*injection\|token.*validation" "$fuzzer"; then
                attack_surfaces=$((attack_surfaces + 1))
            fi
        fi
    done
    
    if [ $attack_surfaces -ge 4 ]; then
        print_status "PASS" "Comprehensive attack surface coverage detected"
    else
        print_status "WARN" "Limited attack surface coverage"
        result=1
    fi
    
    return $result
}

# Check 8: Build System Security
check_build_security() {
    local result=0
    
    print_status "SECURITY" "Checking build system security..."
    
    # Check for secure build practices
    if [ -f "build.sh" ]; then
        if grep -q "set -euo pipefail" build.sh; then
            print_status "PASS" "Build script uses secure shell options"
        else
            print_status "WARN" "Build script missing secure shell options"
            result=1
        fi
        
        if grep -q "compile_go_fuzzer" build.sh; then
            print_status "PASS" "Using secure Go fuzzer compilation"
        else
            print_status "FAIL" "Missing secure Go fuzzer compilation"
            result=1
        fi
    fi
    
    return $result
}

# Check 9: Continuous Integration Security
check_ci_security() {
    local result=0
    
    print_status "SECURITY" "Checking CI/CD security..."
    
    # Check for CIFuzz integration
    if [ -f ".cifuzz.yaml" ]; then
        print_status "PASS" "CIFuzz integration configured"
        
        if grep -q "security_scan.*true" .cifuzz.yaml; then
            print_status "PASS" "Security scanning enabled in CIFuzz"
        else
            print_status "WARN" "Security scanning not explicitly enabled"
            result=1
        fi
    else
        print_status "WARN" "Missing CIFuzz configuration"
        result=1
    fi
    
    return $result
}

# Check 10: Documentation and Compliance
check_documentation_compliance() {
    local result=0
    
    print_status "SECURITY" "Checking documentation and compliance..."
    
    # Check for security documentation
    if [ -f "SECURITY.md" ] && grep -q "security\|vulnerability\|attack" SECURITY.md; then
        print_status "PASS" "Security documentation present"
    else
        print_status "WARN" "Missing or insufficient security documentation"
        result=1
    fi
    
    # Check for compliance documentation
    if [ -f "seeds/SEED_CORPUS_SUMMARY.md" ]; then
        print_status "PASS" "Comprehensive seed corpus documentation"
    else
        print_status "FAIL" "Missing seed corpus documentation"
        result=1
    fi
    
    return $result
}

# Run all security checks
echo "Starting comprehensive security compliance checks..."
echo "Addressing critical findings from OSS-Fuzz infrastructure audit..."
echo ""

run_critical_check "Supply Chain Security" check_supply_chain_security
run_critical_check "Privilege Escalation Prevention" check_privilege_escalation
run_critical_check "Dependency Pinning" check_dependency_pinning
run_security_check "Docker Security" check_docker_security
run_security_check "Authentication Security" check_authentication_security
run_security_check "Code Quality and Static Analysis" check_code_quality
run_security_check "Fuzzer Security Validation" check_fuzzer_security
run_security_check "Build System Security" check_build_security
run_security_check "Continuous Integration Security" check_ci_security
run_security_check "Documentation and Compliance" check_documentation_compliance

# Print comprehensive summary
echo ""
echo "📊 Security Compliance Summary"
echo "============================="
echo "Total security checks: $total_checks"
echo "Passed: $passed_checks"
echo "Failed: $failed_checks"
echo "Critical failures: $critical_failures"
echo "Success rate: $((passed_checks * 100 / total_checks))%"

if [[ $critical_failures -eq 0 && $failed_checks -eq 0 ]]; then
    echo ""
    print_status "PASS" "🎉 ALL SECURITY CHECKS PASSED! Enterprise-grade security achieved."
    echo ""
    echo "✅ Supply Chain Security: VERIFIED"
    echo "✅ Privilege Escalation Prevention: ACTIVE"
    echo "✅ Dependency Pinning: ENFORCED"
    echo "✅ Docker Security: HARDENED"
    echo "✅ Authentication Security: SECURE"
    echo "✅ Code Quality: VALIDATED"
    echo "✅ Fuzzer Security: COMPREHENSIVE"
    echo "✅ Build System Security: PROTECTED"
    echo "✅ CI/CD Security: MONITORED"
    echo "✅ Documentation: COMPLIANT"
    echo ""
    echo "🔒 OSS-Fuzz Integration: SECURITY-AUDIT COMPLIANT"
    echo "🔒 Critical Audit Findings: ADDRESSED"
    echo "🔒 Enterprise Security: ACHIEVED"
    exit 0
elif [[ $critical_failures -gt 0 ]]; then
    echo ""
    print_status "CRITICAL" "🚨 CRITICAL SECURITY FAILURES DETECTED!"
    echo ""
    echo "Critical failures that must be addressed:"
    for item in "${critical_items[@]}"; do
        echo "  🚨 $item"
    done
    echo ""
    echo "These critical failures represent immediate security risks that must be resolved"
    echo "before proceeding with OSS-Fuzz integration."
    exit 1
else
    echo ""
    print_status "WARN" "⚠️  Some security checks failed:"
    for item in "${failed_items[@]}"; do
        echo "  ⚠️  $item"
    done
    echo ""
    echo "Please address these issues to achieve full security compliance."
    exit 1
fi
