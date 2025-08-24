#!/bin/bash
# OSS-Fuzz Integration Validation Script
# Tests all components of the tri-language fuzzing setup

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== OSS-Fuzz Integration Validator for Gemini CLI ==="
echo "Testing tri-language fuzzing setup..."

# Check environment
check_env() {
    echo -e "\n${YELLOW}[1/7] Checking Environment${NC}"
    
    if [ -z "${SRC:-}" ]; then
        export SRC="/src"
        echo "  SRC not set, using default: $SRC"
    fi
    
    if [ -z "${OUT:-}" ]; then
        export OUT="/out"
        echo "  OUT not set, using default: $OUT"
    fi
    
    if [ -z "${CC:-}" ]; then
        export CC="clang"
        echo "  CC not set, using default: $CC"
    fi
    
    echo -e "  ${GREEN}✓ Environment configured${NC}"
}
# Check Go installation
check_go() {
    echo -e "\n${YELLOW}[2/7] Checking Go Installation${NC}"
    
    if ! command -v go &> /dev/null; then
        echo -e "  ${RED}✗ Go not installed${NC}"
        return 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}')
    echo "  Go version: $GO_VERSION"
    
    # Check Go modules
    if [ -f "gofuzz/go.mod" ]; then
        echo -e "  ${GREEN}✓ Go modules found${NC}"
    else
        echo -e "  ${RED}✗ go.mod not found${NC}"
        return 1
    fi
}

# Check Node.js installation
check_node() {
    echo -e "\n${YELLOW}[3/7] Checking Node.js Installation${NC}"
    
    if ! command -v node &> /dev/null; then
        echo -e "  ${RED}✗ Node.js not installed${NC}"
        return 1
    fi
    
    NODE_VERSION=$(node --version)
    echo "  Node.js version: $NODE_VERSION"    
    if ! command -v npm &> /dev/null; then
        echo -e "  ${RED}✗ npm not installed${NC}"
        return 1
    fi
    
    NPM_VERSION=$(npm --version)
    echo "  npm version: $NPM_VERSION"
    
    # Check package.json
    if [ -f "fuzzers/package.json" ]; then
        echo -e "  ${GREEN}✓ package.json found${NC}"
    else
        echo -e "  ${RED}✗ package.json not found${NC}"
        return 1
    fi
}

# Validate critical fuzzers
check_critical_fuzzers() {
    echo -e "\n${YELLOW}[4/7] Checking Critical Security Fuzzers${NC}"
    
    CRITICAL_FUZZERS=(
        "fuzz_symlink_validation"    # Issue #1121
        "fuzz_path_validation"        # Path traversal
        "fuzz_context_file_parser"    # Prompt injection
        "fuzz_shell_validation"       # Command injection
    )
    
    for fuzzer in "${CRITICAL_FUZZERS[@]}"; do
        if [ -f "gofuzz/fuzz/${fuzzer}.go" ]; then
            echo -e "  ${GREEN}✓ $fuzzer found${NC}"        else
            echo -e "  ${RED}✗ $fuzzer not found - CRITICAL!${NC}"
            return 1
        fi
    done
}

# Check seed corpus
check_seeds() {
    echo -e "\n${YELLOW}[5/7] Checking Seed Corpus${NC}"
    
    CRITICAL_SEEDS=(
        "FuzzSymlinkValidation"
        "FuzzContextFileParser"
        "FuzzPathValidation"
        "FuzzShellValidation"
    )
    
    for seed_dir in "${CRITICAL_SEEDS[@]}"; do
        if [ -d "seeds/$seed_dir" ]; then
            count=$(find "seeds/$seed_dir" -type f | wc -l)
            echo -e "  ${GREEN}✓ $seed_dir: $count seed files${NC}"
        else
            echo -e "  ${YELLOW}⚠ $seed_dir directory not found${NC}"
        fi
    done
}

# Check dictionaries
check_dictionaries() {
    echo -e "\n${YELLOW}[6/7] Checking Dictionaries${NC}"
        REQUIRED_DICTS=(
        "path.dict"
        "json.dict"
        "cli.dict"
        "url.dict"
    )
    
    for dict in "${REQUIRED_DICTS[@]}"; do
        if [ -f "fuzzers/dictionaries/$dict" ]; then
            lines=$(wc -l < "fuzzers/dictionaries/$dict")
            echo -e "  ${GREEN}✓ $dict: $lines entries${NC}"
        else
            echo -e "  ${YELLOW}⚠ $dict not found${NC}"
        fi
    done
}

# Test build process
test_build() {
    echo -e "\n${YELLOW}[7/7] Testing Build Process${NC}"
    
    # Test if build script exists and is executable
    if [ -f "build.sh" ]; then
        if [ -x "build.sh" ]; then
            echo -e "  ${GREEN}✓ build.sh is executable${NC}"
        else
            echo -e "  ${YELLOW}⚠ build.sh not executable, fixing...${NC}"
            chmod +x build.sh
        fi
    else
        echo -e "  ${RED}✗ build.sh not found${NC}"
        return 1
    fi    
    # Check Dockerfile
    if [ -f "Dockerfile" ]; then
        echo -e "  ${GREEN}✓ Dockerfile found${NC}"
    else
        echo -e "  ${RED}✗ Dockerfile not found${NC}"
        return 1
    fi
    
    # Check project.yaml
    if [ -f "project.yaml" ]; then
        # Validate critical fields
        if grep -q "primary_contact:" project.yaml; then
            echo -e "  ${GREEN}✓ project.yaml has primary_contact${NC}"
        else
            echo -e "  ${RED}✗ project.yaml missing primary_contact${NC}"
        fi
    else
        echo -e "  ${RED}✗ project.yaml not found${NC}"
        return 1
    fi
}

# Main execution
main() {
    FAILED=0
    
    check_env || FAILED=1
    check_go || FAILED=1
    check_node || FAILED=1
    check_critical_fuzzers || FAILED=1
    check_seeds || FAILED=1    check_dictionaries || FAILED=1
    test_build || FAILED=1
    
    echo -e "\n${YELLOW}=== Validation Summary ===${NC}"
    
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All checks passed!${NC}"
        echo -e "${GREEN}✓ Ready for OSS-Fuzz integration${NC}"
        echo -e "${GREEN}✓ Focus on Issue #1121 (symlink traversal)${NC}"
        
        # Additional recommendations
        echo -e "\n${YELLOW}Recommendations:${NC}"
        echo "1. Update PR #13770 with these improvements"
        echo "2. Tag @NTaylorMullen for review"
        echo "3. Reference Issue #1121 in PR description"
        echo "4. Request expedited review due to P0 vulnerability"
        
        exit 0
    else
        echo -e "${RED}✗ Validation failed!${NC}"
        echo -e "${RED}Please fix the issues above before submitting.${NC}"
        
        exit 1
    fi
}

# Run validation
main "$@"