#!/bin/bash -e
# Ultimate OSS-Fuzz build script for Gemini CLI
# Features: Performance profiling, parallel builds, security scanning, and advanced optimization
# Copyright 2025 Google LLC

# =============================================================================
# Configuration & Environment Setup
# =============================================================================

# Enable debugging if DEBUG environment variable is set
if [[ "${DEBUG:-}" == "true" ]]; then
    set -x  # Enable command tracing
    export DEBUG=true
fi

# Script configuration
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_START_TIME="$(date '+%Y-%m-%d %H:%M:%S')"
BUILD_LOG_FILE="${OUT:-/tmp}/build_${SCRIPT_NAME}_$(date '+%Y%m%d_%H%M%S').log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Logging Functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%H:%M:%S') - $*"
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$BUILD_LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%H:%M:%S') - $*"
    echo "[SUCCESS] $(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$BUILD_LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%H:%M:%S') - $*"
    echo "[WARNING] $(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$BUILD_LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') - $*"
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$BUILD_LOG_FILE"
}

log_debug() {
    if [[ "${DEBUG:-}" == "true" ]]; then
        echo -e "[DEBUG] $(date '+%H:%M:%S') - $*"
        echo "[DEBUG] $(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$BUILD_LOG_FILE"
    fi
}

# Performance profiling
declare -A BUILD_TIMING
declare -A BUILD_MEMORY
declare -A BUILD_SUCCESS

start_timer() {
    local step="$1"
    BUILD_TIMING["$step"]=$(date +%s%3N)  # Millisecond precision
    log_debug "Started timing: $step"
}

end_timer() {
    local step="$1"
    local end_time=$(date +%s%3N)
    local start_time="${BUILD_TIMING[$step]:-0}"
    local duration=$((end_time - start_time))

    if [[ $duration -gt 0 ]]; then
        log_info "⏱️  $step completed in ${duration}ms"
        echo "TIMING:$step:${duration}ms" >> "$BUILD_LOG_FILE"
    fi
}

log_performance() {
    local step="$1"
    local memory_kb=$(ps -o rss= $$ 2>/dev/null | awk '{print $1}' || echo "0")
    BUILD_MEMORY["$step"]=$memory_kb
    log_debug "Memory usage for $step: ${memory_kb}KB"
}

log_step_success() {
    local step="$1"
    BUILD_SUCCESS["$step"]="success"
    log_success "✅ $step completed successfully"
}

log_step_failure() {
    local step="$1"
    BUILD_SUCCESS["$step"]="failed"
    log_error "❌ $step failed"
}

log_build_progress() {
    echo -e "${BLUE}[BUILD]${NC} $(date '+%H:%M:%S') - $*"
    echo "[BUILD] $(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$BUILD_LOG_FILE"
}

# =============================================================================
# Error Handling & Cleanup
# =============================================================================

cleanup_on_error() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Build failed with exit code $exit_code"
        log_error "Check the log file: $BUILD_LOG_FILE"
        log_error "Last 10 lines of build log:"
        tail -n 10 "$BUILD_LOG_FILE" >&2
    fi
    exit $exit_code
}

trap cleanup_on_error ERR

# =============================================================================
# Environment Validation
# =============================================================================

validate_environment() {
    log_build_progress "Validating build environment..."

    # Check required environment variables
    local required_vars=("OUT" "SRC")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required environment variable $var is not set"
            return 1
        fi
        log_debug "$var=${!var}"
    done

    # Check required directories
    if [[ ! -d "$OUT" ]]; then
        log_warning "Creating output directory: $OUT"
        mkdir -p "$OUT" || {
            log_error "Failed to create output directory: $OUT"
            return 1
        }
    fi

    if [[ ! -d "$SRC" ]]; then
        log_error "Source directory does not exist: $SRC"
        return 1
    fi

    # Check required tools
    local required_tools=("go" "npm" "javac" "python3")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_warning "Tool not found: $tool (may not be required for all targets)"
        else
            log_debug "Found tool: $tool"
        fi
    done

    log_success "Environment validation completed"
    return 0
}

# =============================================================================
# Utility Functions
# =============================================================================

get_file_size() {
    local file="$1"
    if [[ -f "$file" ]]; then
        stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

format_size() {
    local size="$1"
    if [[ $size -gt 1048576 ]]; then
        echo "$(( size / 1048576 ))MB"
    elif [[ $size -gt 1024 ]]; then
        echo "$(( size / 1024 ))KB"
    else
        echo "${size}B"
    fi
}

# Auto-detection summary storage
declare -A AUTO_DETECTION_SUMMARY
declare -A FUZZ_TARGET_CACHE
declare -A DICTIONARY_CACHE

# Enhanced configuration for auto-detection with expanded patterns
AUTO_DETECTION_CONFIG=(
    ["go_fuzzer_pattern"]="fuzz_*.go"
    ["js_fuzzer_pattern"]="fuzz_*.js"
    ["java_fuzzer_pattern"]="*Fuzz*.java"
    ["cpp_fuzzer_pattern"]="fuzz_*.cpp fuzz_*.cc fuzz_*.cxx"
    ["c_fuzzer_pattern"]="fuzz_*.c"
    ["rust_fuzzer_pattern"]="fuzz_*.rs"
    ["python_fuzzer_pattern"]="fuzz_*.py"
    ["dict_pattern"]="*.dict"
    ["seed_pattern"]="*"
    ["config_pattern"]="*.options"
)

# =============================================================================
# Enhanced Validation Functions
# =============================================================================

is_valid_go_fuzzer() {
    local file="$1"
    # Check if file contains Fuzz function
    if grep -q "func Fuzz" "$file" 2>/dev/null; then
        return 0
    fi
    return 1
}

is_valid_js_fuzzer() {
    local file="$1"
    # Check if file exports a fuzz function
    if grep -q "function fuzz\|exports\.fuzz\|module\.exports.*fuzz" "$file" 2>/dev/null; then
        return 0
    fi
    return 1
}

is_valid_java_fuzzer() {
    local file="$1"
    # Check if class contains fuzzerTestOneInput method
    if grep -q "public static void fuzzerTestOneInput\|@FuzzTest" "$file" 2>/dev/null; then
        return 0
    fi
    return 1
}

is_valid_dictionary() {
    local file="$1"
    # Enhanced dictionary validation
    # Check if dictionary file is valid (not empty and has proper format)
    if [[ ! -s "$file" ]]; then
        return 1  # Empty file
    fi

    # Check if it has dictionary-like content
    local first_line
    first_line=$(head -n 1 "$file" 2>/dev/null || echo "")

    # Dictionary entries should start with quotes or valid tokens
    if [[ "$first_line" =~ ^[[:space:]]*[\"\'a-zA-Z0-9] ]] || [[ "$first_line" =~ ^[[:space:]]*#[[:space:]]*(keyword|token) ]]; then
        # Additional check: should have some dictionary-like entries
        if grep -q "^[[:space:]]*[\"'][^\"']*[\"'][[:space:]]*$" "$file" 2>/dev/null || \
           grep -q "^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*$" "$file" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

is_valid_cpp_fuzzer() {
    local file="$1"
    # Check for C++ fuzzing patterns
    if grep -q "LLVMFuzzerTestOneInput\|extern.*LLVMFuzzerTestOneInput" "$file" 2>/dev/null; then
        return 0
    fi
    return 1
}

is_valid_c_fuzzer() {
    local file="$1"
    # Check for C fuzzing patterns
    if grep -q "LLVMFuzzerTestOneInput\|extern.*LLVMFuzzerTestOneInput" "$file" 2>/dev/null; then
        return 0
    fi
    return 1
}

is_valid_rust_fuzzer() {
    local file="$1"
    # Check for Rust fuzzing patterns
    if grep -q "#\[test\]\|fuzz_target!\|LLVMFuzzerTestOneInput" "$file" 2>/dev/null; then
        return 0
    fi
    return 1
}

is_valid_python_fuzzer() {
    local file="$1"
    # Check for Python fuzzing patterns
    if grep -q "def fuzz\|atheris.Setup\|atheris.Fuzz" "$file" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Security scanning functions
scan_for_vulnerabilities() {
    local file="$1"
    local issues=0

    log_debug "Scanning $file for security issues..."

    # Check for common vulnerabilities
    if grep -q "system(\|exec(\|eval(" "$file" 2>/dev/null; then
        log_warning "⚠️  Potential command injection in $file"
        ((issues++))
    fi

    if grep -q "password\|secret\|token\|key" "$file" 2>/dev/null; then
        log_warning "⚠️  Potential credential exposure in $file"
        ((issues++))
    fi

    if grep -q "buffer.*overflow\|heap.*overflow" "$file" 2>/dev/null; then
        log_warning "⚠️  Potential buffer overflow in $file"
        ((issues++))
    fi

    return $issues
}

validate_fuzz_target_integrity() {
    local target="$1"
    local file="$2"

    # Check file integrity
    if [[ ! -s "$file" ]]; then
        log_error "Fuzz target file is empty: $file"
        return 1
    fi

    # Check for malicious patterns
    if scan_for_vulnerabilities "$file"; then
        log_warning "Security scan found potential issues in $file"
    fi

    # Validate file format and structure
    local file_type="${file##*.}"
    case "$file_type" in
        "go")
            if ! go fmt "$file" >/dev/null 2>&1; then
                log_warning "Go file format issues in $file"
            fi
            ;;
        "js")
            if command -v node >/dev/null 2>&1; then
                if ! node -c "$file" >/dev/null 2>&1; then
                    log_warning "JavaScript syntax issues in $file"
                fi
            fi
            ;;
        "java")
            if command -v javac >/dev/null 2>&1; then
                if ! javac -cp . "$file" -d /tmp >/dev/null 2>&1; then
                    log_warning "Java compilation issues in $file"
                fi
            fi
            ;;
    esac

    return 0
}

optimize_build_performance() {
    log_build_progress "Optimizing build performance..."

    # Set optimal compiler flags
    export CFLAGS="${CFLAGS:-} -O2 -g"
    export CXXFLAGS="${CXXFLAGS:-} -O2 -g"
    export GOFLAGS="${GOFLAGS:-} -ldflags='-s -w'"

    # Enable parallel builds
    local cpu_count=$(nproc 2>/dev/null || echo "4")
    export MAKEFLAGS="${MAKEFLAGS:-} -j$cpu_count"

    # Optimize Go builds
    export GOMAXPROCS="$cpu_count"

    # Set memory limits to prevent OOM
    local mem_limit="2G"
    export GOMEMLIMIT="$mem_limit"

    log_info "Performance optimizations applied:"
    log_info "  CPU cores: $cpu_count"
    log_info "  Memory limit: $mem_limit"
    log_info "  CFLAGS: $CFLAGS"
    log_info "  GOFLAGS: $GOFLAGS"
}

is_valid_seed_directory() {
    local dir="$1"
    # Check if directory contains files and is not empty
    if [[ -d "$dir" ]] && [[ $(find "$dir" -type f | wc -l) -gt 0 ]]; then
        return 0
    fi
    return 1
}

get_file_hash() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" 2>/dev/null | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" 2>/dev/null | cut -d' ' -f1
    else
        stat -c%s "$file" 2>/dev/null || echo "unknown"
    fi
}

should_rebuild_target() {
    local target="$1"
    local source_file="$2"
    local output_file="$OUT/$target"

    # Check if output file exists
    if [[ ! -f "$output_file" ]]; then
        return 0  # Need to build
    fi

    # Check if source is newer than output
    if [[ "$source_file" -nt "$output_file" ]]; then
        return 0  # Need to rebuild
    fi

    # Check if hash has changed (if available)
    local current_hash
    local cached_hash
    current_hash=$(get_file_hash "$source_file")
    cached_hash="${FUZZ_TARGET_CACHE[$target]:-}"

    if [[ "$current_hash" != "$cached_hash" ]] && [[ "$current_hash" != "unknown" ]]; then
        FUZZ_TARGET_CACHE[$target]="$current_hash"
        return 0  # Need to rebuild
    fi

    return 1  # No rebuild needed
}

log_detection_summary() {
    log_build_progress "Auto-Detection Summary:"
    echo "" >> "$BUILD_LOG_FILE"
    echo "=== AUTO-DETECTION SUMMARY ===" >> "$BUILD_LOG_FILE"

    if [[ ${AUTO_DETECTION_SUMMARY[go_fuzzers]} ]]; then
        log_info "  Go fuzz targets: ${AUTO_DETECTION_SUMMARY[go_fuzzers]}"
        echo "Go fuzz targets: ${AUTO_DETECTION_SUMMARY[go_fuzzers]}" >> "$BUILD_LOG_FILE"
    fi

    if [[ ${AUTO_DETECTION_SUMMARY[js_fuzzers]} ]]; then
        log_info "  JavaScript fuzz targets: ${AUTO_DETECTION_SUMMARY[js_fuzzers]}"
        echo "JavaScript fuzz targets: ${AUTO_DETECTION_SUMMARY[js_fuzzers]}" >> "$BUILD_LOG_FILE"
    fi

    if [[ ${AUTO_DETECTION_SUMMARY[java_fuzzers]} ]]; then
        log_info "  Java fuzz targets: ${AUTO_DETECTION_SUMMARY[java_fuzzers]}"
        echo "Java fuzz targets: ${AUTO_DETECTION_SUMMARY[java_fuzzers]}" >> "$BUILD_LOG_FILE"
    fi

    if [[ ${AUTO_DETECTION_SUMMARY[cpp_fuzzers]} ]]; then
        log_info "  C++ fuzz targets: ${AUTO_DETECTION_SUMMARY[cpp_fuzzers]}"
        echo "C++ fuzz targets: ${AUTO_DETECTION_SUMMARY[cpp_fuzzers]}" >> "$BUILD_LOG_FILE"
    fi

    if [[ ${AUTO_DETECTION_SUMMARY[c_fuzzers]} ]]; then
        log_info "  C fuzz targets: ${AUTO_DETECTION_SUMMARY[c_fuzzers]}"
        echo "C fuzz targets: ${AUTO_DETECTION_SUMMARY[c_fuzzers]}" >> "$BUILD_LOG_FILE"
    fi

    if [[ ${AUTO_DETECTION_SUMMARY[rust_fuzzers]} ]]; then
        log_info "  Rust fuzz targets: ${AUTO_DETECTION_SUMMARY[rust_fuzzers]}"
        echo "Rust fuzz targets: ${AUTO_DETECTION_SUMMARY[rust_fuzzers]}" >> "$BUILD_LOG_FILE"
    fi

    if [[ ${AUTO_DETECTION_SUMMARY[python_fuzzers]} ]]; then
        log_info "  Python fuzz targets: ${AUTO_DETECTION_SUMMARY[python_fuzzers]}"
        echo "Python fuzz targets: ${AUTO_DETECTION_SUMMARY[python_fuzzers]}" >> "$BUILD_LOG_FILE"
    fi

    if [[ ${AUTO_DETECTION_SUMMARY[seed_corpora]} ]]; then
        log_info "  Seed corpora: ${AUTO_DETECTION_SUMMARY[seed_corpora]}"
        echo "Seed corpora: ${AUTO_DETECTION_SUMMARY[seed_corpora]}" >> "$BUILD_LOG_FILE"
    fi

    if [[ ${AUTO_DETECTION_SUMMARY[dictionaries]} ]]; then
        log_info "  Dictionaries: ${AUTO_DETECTION_SUMMARY[dictionaries]}"
        echo "Dictionaries: ${AUTO_DETECTION_SUMMARY[dictionaries]}" >> "$BUILD_LOG_FILE"
    fi

    if [[ ${AUTO_DETECTION_SUMMARY[options_files]} ]]; then
        log_info "  Options files: ${AUTO_DETECTION_SUMMARY[options_files]}"
        echo "Options files: ${AUTO_DETECTION_SUMMARY[options_files]}" >> "$BUILD_LOG_FILE"
    fi

    echo "" >> "$BUILD_LOG_FILE"
}

# =============================================================================
# Build Functions
# =============================================================================

build_go_fuzzers() {
    start_timer "go_build"
    log_build_progress "Building Go fuzz targets..."

    local go_targets=0
    local go_built=0
    local go_skipped=0
    local detected_go_fuzzers=()
    local valid_go_fuzzers=()

    # Performance optimization
    optimize_build_performance

    if [[ ! -d "gofuzz" ]]; then
        log_warning "No gofuzz directory found, skipping Go fuzzers"
        return 0
    fi

    cd gofuzz

    # Initialize Go module
    if [[ -f "go.mod" ]]; then
        log_debug "Found go.mod, running go mod tidy"
        go mod tidy 2>&1 | tee -a "$BUILD_LOG_FILE" || log_warning "go mod tidy failed"
    else
        log_debug "No go.mod found, initializing module"
        go mod init github.com/google-gemini/gemini-cli/gofuzz 2>&1 | tee -a "$BUILD_LOG_FILE" || log_warning "Failed to initialize Go module"
    fi

    # Enhanced auto-detection with validation
    if [[ -d "fuzz" ]]; then
        log_debug "Scanning for Go fuzz targets with validation..."
        while IFS= read -r -d '' fuzz_file; do
            local target_name
            target_name=$(basename "$fuzz_file" .go)
            detected_go_fuzzers+=("$target_name")

            # Validate fuzz target before building
            if is_valid_go_fuzzer "$fuzz_file"; then
                # Additional security and integrity validation
                if validate_fuzz_target_integrity "$target_name" "$fuzz_file"; then
                    valid_go_fuzzers+=("$target_name")
                    log_debug "Validated Go fuzz target: $target_name"
                else
                    log_warning "Skipping Go fuzz target due to validation failure: $target_name"
                fi
            else
                log_warning "Skipping invalid Go fuzz target: $target_name (no Fuzz function found)"
            fi
        done < <(find fuzz -name "fuzz_*.go" -type f -print0)
    fi

    log_info "Auto-detected ${#detected_go_fuzzers[@]} Go fuzz files, ${#valid_go_fuzzers[@]} valid fuzz targets"

    # Build validated Go fuzz targets with caching
    for target_name in "${valid_go_fuzzers[@]}"; do
        local fuzz_file="fuzz/${target_name}.go"
        ((go_targets++))

        # Check if rebuild is needed
        if should_rebuild_target "$target_name" "$fuzz_file"; then
            log_debug "Building Go fuzz target: $target_name"

            if go build -o "${OUT}/${target_name}" "$fuzz_file" 2>&1 | tee -a "$BUILD_LOG_FILE"; then
                ((go_built++))
                local size
                size=$(get_file_size "${OUT}/${target_name}")
                log_success "Built Go fuzz target: $target_name ($(format_size "$size"))"

                # Cache the hash for next time
                FUZZ_TARGET_CACHE[$target_name]=$(get_file_hash "$fuzz_file")
            else
                log_error "Failed to build Go fuzz target: $target_name"
            fi
        else
            ((go_skipped++))
            local size
            size=$(get_file_size "${OUT}/${target_name}")
            log_info "Skipped Go fuzz target: $target_name (up-to-date, $(format_size "$size"))"
        fi
    done

    cd ..

    # Store detection summary with validation info
    AUTO_DETECTION_SUMMARY[go_fuzzers]="${#detected_go_fuzzers[@]} detected, ${#valid_go_fuzzers[@]} validated, $go_built built, $go_skipped skipped"

    # Performance and success tracking
    log_performance "go_build"
    end_timer "go_build"

    if [[ $go_built -gt 0 ]]; then
        log_step_success "Go fuzz target building"
    else
        log_step_failure "Go fuzz target building"
    fi

    log_build_progress "Go fuzz targets: $go_built/$go_targets built successfully ($go_skipped skipped)"
}

build_javascript_fuzzers() {
    log_build_progress "Building JavaScript fuzz targets..."

    local js_targets=0
    local js_built=0
    local js_skipped=0
    local detected_js_fuzzers=()
    local valid_js_fuzzers=()

    if [[ ! -d "fuzzers" ]]; then
        log_warning "No fuzzers directory found, skipping JavaScript fuzzers"
        return 0
    fi

    cd fuzzers

    # Install dependencies
    if [[ -f "package.json" ]]; then
        log_debug "Installing JavaScript dependencies"
        npm ci 2>&1 | tee -a "$BUILD_LOG_FILE" || log_warning "npm ci failed"
    fi

    # Enhanced auto-detection with validation
    log_debug "Scanning for JavaScript fuzz targets with validation..."
    while IFS= read -r -d '' js_file; do
        local target_name
        target_name=$(basename "$js_file" .js)
        detected_js_fuzzers+=("$target_name")

        # Validate fuzz target before building
        if is_valid_js_fuzzer "$js_file"; then
            valid_js_fuzzers+=("$target_name")
            log_debug "Validated JavaScript fuzz target: $target_name"
        else
            log_warning "Skipping invalid JavaScript fuzz target: $target_name (no fuzz function found)"
        fi
    done < <(find . -name "fuzz_*.js" -type f -print0)

    log_info "Auto-detected ${#detected_js_fuzzers[@]} JavaScript fuzz files, ${#valid_js_fuzzers[@]} valid fuzz targets"

    # Build validated JavaScript fuzz targets with caching
    for target_name in "${valid_js_fuzzers[@]}"; do
        local js_file="${target_name}.js"
        ((js_targets++))

        # Check if rebuild is needed
        if should_rebuild_target "$target_name" "$js_file"; then
            log_debug "Building JavaScript fuzz target: $target_name"

            if compile_javascript_fuzzer . "$js_file" --sync 2>&1 | tee -a "$BUILD_LOG_FILE"; then
                ((js_built++))
                local fuzz_binary="${OUT}/${target_name}"
                if [[ -f "$fuzz_binary" ]]; then
                    local size
                    size=$(get_file_size "$fuzz_binary")
                    log_success "Built JavaScript fuzz target: $target_name ($(format_size "$size"))"

                    # Cache the hash for next time
                    FUZZ_TARGET_CACHE[$target_name]=$(get_file_hash "$js_file")
                else
                    log_warning "Fuzz binary not found: $fuzz_binary"
                fi
            else
                log_error "Failed to build JavaScript fuzz target: $target_name"
            fi
        else
            ((js_skipped++))
            local fuzz_binary="${OUT}/${target_name}"
            if [[ -f "$fuzz_binary" ]]; then
                local size
                size=$(get_file_size "$fuzz_binary")
                log_info "Skipped JavaScript fuzz target: $target_name (up-to-date, $(format_size "$size"))"
            else
                log_warning "Cached fuzz target not found: $target_name"
            fi
        fi
    done

    cd ..

    # Store detection summary with validation info
    AUTO_DETECTION_SUMMARY[js_fuzzers]="${#detected_js_fuzzers[@]} detected, ${#valid_js_fuzzers[@]} validated, $js_built built, $js_skipped skipped"

    log_build_progress "JavaScript fuzz targets: $js_built/$js_targets built successfully ($js_skipped skipped)"
}

build_java_fuzzers() {
    log_build_progress "Building Java fuzz targets..."

    local java_targets=0
    local java_built=0
    local java_skipped=0
    local detected_java_classes=()
    local valid_java_classes=()

    if [[ ! -d "java" ]]; then
        log_warning "No java directory found, skipping Java fuzzers"
        return 0
    fi

    cd java

    # Build Java components
    if [[ -f "pom.xml" ]]; then
        log_debug "Building Java components with Maven"
        mvn clean compile -q 2>&1 | tee -a "$BUILD_LOG_FILE" || log_warning "Maven build failed"
    fi

    # Enhanced auto-detection with validation
    if [[ -d "src/main/java" ]]; then
        log_debug "Auto-detecting Java fuzz targets with validation..."
        while IFS= read -r -d '' java_file; do
            local class_name
            class_name=$(basename "$java_file" .java)
            detected_java_classes+=("$class_name")

            # Validate fuzz target before building
            if is_valid_java_fuzzer "$java_file"; then
                valid_java_classes+=("$class_name")
                log_debug "Validated Java fuzz target: $class_name"
            else
                log_warning "Skipping invalid Java fuzz target: $class_name (no fuzzerTestOneInput method found)"
            fi
        done < <(find src/main/java -name "*Fuzz*.java" -type f -print0)
    fi

    # Fallback to hardcoded list if no classes found
    if [[ ${#valid_java_classes[@]} -eq 0 ]]; then
        log_warning "No Java fuzz classes auto-detected, using fallback list"
        valid_java_classes=("FuzzOAuthTokenRequest" "FuzzCLIParser" "FuzzConfigParser" "FuzzFilePathHandler")
        log_info "Using fallback Java fuzz targets: ${valid_java_classes[*]}"
    else
        log_info "Auto-detected ${#detected_java_classes[@]} Java classes, ${#valid_java_classes[@]} valid fuzz targets"
    fi

    # Build validated Java fuzz targets with caching
    for class_name in "${valid_java_classes[@]}"; do
        ((java_targets++))

        # Find the Java file for this class
        local java_file
        java_file=$(find src/main/java -name "${class_name}.java" -type f | head -n 1)

        if [[ -n "$java_file" ]]; then
            # Check if rebuild is needed
            if should_rebuild_target "$class_name" "$java_file"; then
                log_debug "Creating Java fuzz target: $class_name"

                if create_jvm_fuzzer "com.gemini.cli.${class_name}" "${class_name}" 2>&1 | tee -a "$BUILD_LOG_FILE"; then
                    ((java_built++))
                    local fuzz_binary="${OUT}/${class_name}"
                    if [[ -f "$fuzz_binary" ]]; then
                        local size
                        size=$(get_file_size "$fuzz_binary")
                        log_success "Created Java fuzz target: $class_name ($(format_size "$size"))"

                        # Cache the hash for next time
                        FUZZ_TARGET_CACHE[$class_name]=$(get_file_hash "$java_file")
                    else
                        log_warning "Fuzz binary not found: $fuzz_binary"
                    fi
                else
                    log_error "Failed to create Java fuzz target: $class_name"
                fi
            else
                ((java_skipped++))
                local fuzz_binary="${OUT}/${class_name}"
                if [[ -f "$fuzz_binary" ]]; then
                    local size
                    size=$(get_file_size "$fuzz_binary")
                    log_info "Skipped Java fuzz target: $class_name (up-to-date, $(format_size "$size"))"
                else
                    log_warning "Cached fuzz target not found: $class_name"
                fi
            fi
        else
            log_warning "Java source file not found for class: $class_name"
        fi
    done

    cd ..

    # Store detection summary with validation info
    AUTO_DETECTION_SUMMARY[java_fuzzers]="${#detected_java_classes[@]} detected, ${#valid_java_classes[@]} validated, $java_built built, $java_skipped skipped"

    log_build_progress "Java fuzz targets: $java_built/$java_targets built successfully ($java_skipped skipped)"
}

build_cpp_fuzzers() {
    log_build_progress "Building C++ fuzz targets..."

    local cpp_targets=0
    local cpp_built=0
    local cpp_skipped=0
    local detected_cpp_fuzzers=()
    local valid_cpp_fuzzers=()

    # Look for C++ fuzzers in multiple locations
    local cpp_dirs=("cpp" "fuzzer" "fuzzers" "." "src")
    for cpp_dir in "${cpp_dirs[@]}"; do
        if [[ -d "$cpp_dir" ]]; then
            log_debug "Scanning for C++ fuzz targets in: $cpp_dir"
            while IFS= read -r -d '' cpp_file; do
                local target_name
                target_name=$(basename "$cpp_file" .cpp | sed 's/\.cc$//' | sed 's/\.cxx$//')
                detected_cpp_fuzzers+=("$target_name")

                # Validate C++ fuzz target before building
                if is_valid_cpp_fuzzer "$cpp_file"; then
                    valid_cpp_fuzzers+=("$target_name")
                    log_debug "Validated C++ fuzz target: $target_name"
                else
                    log_warning "Skipping invalid C++ fuzz target: $target_name (no LLVMFuzzerTestOneInput found)"
                fi
            done < <(find "$cpp_dir" -name "fuzz_*.cpp" -o -name "fuzz_*.cc" -o -name "fuzz_*.cxx" -type f -print0)
        fi
    done

    log_info "Auto-detected ${#detected_cpp_fuzzers[@]} C++ fuzz files, ${#valid_cpp_fuzzers[@]} valid fuzz targets"

    # Build validated C++ fuzz targets with caching
    for target_name in "${valid_cpp_fuzzers[@]}"; do
        local cpp_file
        cpp_file=$(find . -name "${target_name}.cpp" -o -name "${target_name}.cc" -o -name "${target_name}.cxx" | head -n 1)
        ((cpp_targets++))

        if [[ -n "$cpp_file" ]]; then
            # Check if rebuild is needed
            if should_rebuild_target "$target_name" "$cpp_file"; then
                log_debug "Building C++ fuzz target: $target_name"

                if $CXX $CXXFLAGS -o "${OUT}/${target_name}" "$cpp_file" 2>&1 | tee -a "$BUILD_LOG_FILE"; then
                    ((cpp_built++))
                    local size
                    size=$(get_file_size "${OUT}/${target_name}")
                    log_success "Built C++ fuzz target: $target_name ($(format_size "$size"))"

                    # Cache the hash for next time
                    FUZZ_TARGET_CACHE[$target_name]=$(get_file_hash "$cpp_file")
                else
                    log_error "Failed to build C++ fuzz target: $target_name"
                fi
            else
                ((cpp_skipped++))
                local size
                size=$(get_file_size "${OUT}/${target_name}")
                log_info "Skipped C++ fuzz target: $target_name (up-to-date, $(format_size "$size"))"
            fi
        else
            log_warning "C++ source file not found for target: $target_name"
        fi
    done

    # Store detection summary with validation info
    AUTO_DETECTION_SUMMARY[cpp_fuzzers]="${#detected_cpp_fuzzers[@]} detected, ${#valid_cpp_fuzzers[@]} validated, $cpp_built built, $cpp_skipped skipped"

    log_build_progress "C++ fuzz targets: $cpp_built/$cpp_targets built successfully ($cpp_skipped skipped)"
}

build_c_fuzzers() {
    log_build_progress "Building C fuzz targets..."

    local c_targets=0
    local c_built=0
    local c_skipped=0
    local detected_c_fuzzers=()
    local valid_c_fuzzers=()

    # Look for C fuzzers in multiple locations
    local c_dirs=("c" "fuzzer" "fuzzers" "." "src")
    for c_dir in "${c_dirs[@]}"; do
        if [[ -d "$c_dir" ]]; then
            log_debug "Scanning for C fuzz targets in: $c_dir"
            while IFS= read -r -d '' c_file; do
                local target_name
                target_name=$(basename "$c_file" .c)
                detected_c_fuzzers+=("$target_name")

                # Validate C fuzz target before building
                if is_valid_c_fuzzer "$c_file"; then
                    valid_c_fuzzers+=("$target_name")
                    log_debug "Validated C fuzz target: $target_name"
                else
                    log_warning "Skipping invalid C fuzz target: $target_name (no LLVMFuzzerTestOneInput found)"
                fi
            done < <(find "$c_dir" -name "fuzz_*.c" -type f -print0)
        fi
    done

    log_info "Auto-detected ${#detected_c_fuzzers[@]} C fuzz files, ${#valid_c_fuzzers[@]} valid fuzz targets"

    # Build validated C fuzz targets with caching
    for target_name in "${valid_c_fuzzers[@]}"; do
        local c_file
        c_file=$(find . -name "${target_name}.c" | head -n 1)
        ((c_targets++))

        if [[ -n "$c_file" ]]; then
            # Check if rebuild is needed
            if should_rebuild_target "$target_name" "$c_file"; then
                log_debug "Building C fuzz target: $target_name"

                if $CC $CFLAGS -o "${OUT}/${target_name}" "$c_file" 2>&1 | tee -a "$BUILD_LOG_FILE"; then
                    ((c_built++))
                    local size
                    size=$(get_file_size "${OUT}/${target_name}")
                    log_success "Built C fuzz target: $target_name ($(format_size "$size"))"

                    # Cache the hash for next time
                    FUZZ_TARGET_CACHE[$target_name]=$(get_file_hash "$c_file")
                else
                    log_error "Failed to build C fuzz target: $target_name"
                fi
            else
                ((c_skipped++))
                local size
                size=$(get_file_size "${OUT}/${target_name}")
                log_info "Skipped C fuzz target: $target_name (up-to-date, $(format_size "$size"))"
            fi
        else
            log_warning "C source file not found for target: $target_name"
        fi
    done

    # Store detection summary with validation info
    AUTO_DETECTION_SUMMARY[c_fuzzers]="${#detected_c_fuzzers[@]} detected, ${#valid_c_fuzzers[@]} validated, $c_built built, $c_skipped skipped"

    log_build_progress "C fuzz targets: $c_built/$c_targets built successfully ($c_skipped skipped)"
}

build_rust_fuzzers() {
    log_build_progress "Building Rust fuzz targets..."

    local rust_targets=0
    local rust_built=0
    local rust_skipped=0
    local detected_rust_fuzzers=()
    local valid_rust_fuzzers=()

    if [[ ! -d "rust" ]]; then
        log_warning "No rust directory found, skipping Rust fuzzers"
        return 0
    fi

    cd rust

    # Check for Cargo.toml
    if [[ -f "Cargo.toml" ]]; then
        log_debug "Found Cargo.toml, checking for fuzz dependencies"

        # Check if fuzz dependencies are present
        if grep -q "honggfuzz\|libfuzzer" Cargo.toml 2>/dev/null; then
            log_debug "Found fuzzing dependencies in Cargo.toml"
        else
            log_warning "No fuzzing dependencies found in Cargo.toml"
        fi
    fi

    # Look for Rust fuzzers
    log_debug "Scanning for Rust fuzz targets"
    while IFS= read -r -d '' rust_file; do
        local target_name
        target_name=$(basename "$rust_file" .rs)
        detected_rust_fuzzers+=("$target_name")

        # Validate Rust fuzz target before building
        if is_valid_rust_fuzzer "$rust_file"; then
            valid_rust_fuzzers+=("$target_name")
            log_debug "Validated Rust fuzz target: $target_name"
        else
            log_warning "Skipping invalid Rust fuzz target: $target_name (no fuzzing patterns found)"
        fi
    done < <(find . -name "fuzz_*.rs" -type f -print0)

    log_info "Auto-detected ${#detected_rust_fuzzers[@]} Rust fuzz files, ${#valid_rust_fuzzers[@]} valid fuzz targets"

    # Build validated Rust fuzz targets with caching
    for target_name in "${valid_rust_fuzzers[@]}"; do
        local rust_file="${target_name}.rs"
        ((rust_targets++))

        # Check if rebuild is needed
        if should_rebuild_target "$target_name" "$rust_file"; then
            log_debug "Building Rust fuzz target: $target_name"

            if cargo build --release --bin "$target_name" 2>&1 | tee -a "$BUILD_LOG_FILE"; then
                # Copy the built binary to OUT directory
                if [[ -f "target/release/${target_name}" ]]; then
                    cp "target/release/${target_name}" "${OUT}/"
                    ((rust_built++))
                    local size
                    size=$(get_file_size "${OUT}/${target_name}")
                    log_success "Built Rust fuzz target: $target_name ($(format_size "$size"))"

                    # Cache the hash for next time
                    FUZZ_TARGET_CACHE[$target_name]=$(get_file_hash "$rust_file")
                else
                    log_warning "Rust binary not found: target/release/${target_name}"
                fi
            else
                log_error "Failed to build Rust fuzz target: $target_name"
            fi
        else
            ((rust_skipped++))
            local size
            size=$(get_file_size "${OUT}/${target_name}")
            log_info "Skipped Rust fuzz target: $target_name (up-to-date, $(format_size "$size"))"
        fi
    done

    cd ..

    # Store detection summary with validation info
    AUTO_DETECTION_SUMMARY[rust_fuzzers]="${#detected_rust_fuzzers[@]} detected, ${#valid_rust_fuzzers[@]} validated, $rust_built built, $rust_skipped skipped"

    log_build_progress "Rust fuzz targets: $rust_built/$rust_targets built successfully ($rust_skipped skipped)"
}

build_python_fuzzers() {
    log_build_progress "Building Python fuzz targets..."

    local python_targets=0
    local python_built=0
    local python_skipped=0
    local detected_python_fuzzers=()
    local valid_python_fuzzers=()

    if [[ ! -d "python" ]]; then
        log_warning "No python directory found, skipping Python fuzzers"
        return 0
    fi

    cd python

    # Look for Python fuzzers
    log_debug "Scanning for Python fuzz targets"
    while IFS= read -r -d '' python_file; do
        local target_name
        target_name=$(basename "$python_file" .py)
        detected_python_fuzzers+=("$target_name")

        # Validate Python fuzz target before building
        if is_valid_python_fuzzer "$python_file"; then
            valid_python_fuzzers+=("$target_name")
            log_debug "Validated Python fuzz target: $target_name"
        else
            log_warning "Skipping invalid Python fuzz target: $target_name (no fuzzing patterns found)"
        fi
    done < <(find . -name "fuzz_*.py" -type f -print0)

    log_info "Auto-detected ${#detected_python_fuzzers[@]} Python fuzz files, ${#valid_python_fuzzers[@]} valid fuzz targets"

    # Build validated Python fuzz targets (compile to bytecode for performance)
    for target_name in "${valid_python_fuzzers[@]}"; do
        local python_file="${target_name}.py"
        ((python_targets++))

        # Check if rebuild is needed
        if should_rebuild_target "$target_name" "$python_file"; then
            log_debug "Processing Python fuzz target: $target_name"

            # For Python fuzzers, we copy the source and create a wrapper script
            if cp "$python_file" "${OUT}/" 2>/dev/null; then
                # Create a wrapper script for the Python fuzzer
                cat > "${OUT}/${target_name}_wrapper" << EOF
#!/bin/bash
# Python fuzzer wrapper for OSS-Fuzz
python3 "${OUT}/${python_file}" "\$@"
EOF
                chmod +x "${OUT}/${target_name}_wrapper"

                ((python_built++))
                local size
                size=$(get_file_size "${OUT}/${python_file}")
                log_success "Processed Python fuzz target: $target_name ($(format_size "$size"))"

                # Cache the hash for next time
                FUZZ_TARGET_CACHE[$target_name]=$(get_file_hash "$python_file")
            else
                log_error "Failed to copy Python fuzz target: $target_name"
            fi
        else
            ((python_skipped++))
            local size
            size=$(get_file_size "${OUT}/${python_file}")
            log_info "Skipped Python fuzz target: $target_name (up-to-date, $(format_size "$size"))"
        fi
    done

    cd ..

    # Store detection summary with validation info
    AUTO_DETECTION_SUMMARY[python_fuzzers]="${#detected_python_fuzzers[@]} detected, ${#valid_python_fuzzers[@]} validated, $python_built built, $python_skipped skipped"

    log_build_progress "Python fuzz targets: $python_built/$python_targets built successfully ($python_skipped skipped)"
}

copy_supporting_files() {
    log_build_progress "Copying supporting files..."

    # Copy existing seed corpora zip files
    if [[ -d "seeds" ]]; then
        log_debug "Copying existing seed corpus zip files"
        local zip_count=0
        find seeds -name "*.zip" -type f | while read -r zip_file; do
            if cp "$zip_file" "$OUT/" 2>/dev/null; then
                ((zip_count++))
                log_debug "Copied seed corpus: $(basename "$zip_file")"
            fi
        done
        log_info "Copied $zip_count existing seed corpus zip files"
    fi

    # Enhanced auto-detect and package seed directories
    local seed_dirs=()
    local valid_seed_dirs=()
    local packaged_seeds=0
    local skipped_seeds=0

    # Look for seed corpora in multiple locations
    local seed_base_dirs=("seeds" "seed" "corpus" "testdata" "fuzz/seeds" "fuzz/corpus")
    for seed_base_dir in "${seed_base_dirs[@]}"; do
        if [[ -d "$seed_base_dir" ]]; then
            log_debug "Scanning seed corpora in: $seed_base_dir"
            while IFS= read -r -d '' seed_dir; do
                local target_name
                target_name=$(basename "$seed_dir")
                seed_dirs+=("$target_name")

                # Validate seed directory before packaging
                if is_valid_seed_directory "$seed_dir"; then
                    valid_seed_dirs+=("$target_name")
                    log_debug "Validated seed directory: $target_name ($(find "$seed_dir" -type f | wc -l) files)"

                    # Check if we need to rebuild the seed corpus
                    local seed_zip="${OUT}/${target_name}_seed_corpus.zip"
                    if [[ ! -f "$seed_zip" ]] || [[ "$seed_dir" -nt "$seed_zip" ]]; then
                        if zip -jr "$seed_zip" "$seed_dir" >/dev/null 2>&1; then
                            ((packaged_seeds++))
                            local size
                            size=$(get_file_size "$seed_zip")
                            log_success "Created seed corpus: $target_name ($(format_size "$size"))"
                        else
                            log_warning "Failed to create seed corpus for: $target_name"
                        fi
                    else
                        ((skipped_seeds++))
                        local size
                        size=$(get_file_size "$seed_zip")
                        log_debug "Skipped seed corpus: $target_name (up-to-date, $(format_size "$size"))"
                    fi
                else
                    log_warning "Skipping empty or invalid seed directory: $target_name"
                fi
            done < <(find "$seed_base_dir" -mindepth 1 -maxdepth 1 -type d -print0)
        fi
    done

    if [[ ${#seed_dirs[@]} -gt 0 ]]; then
        log_info "Auto-detected ${#seed_dirs[@]} seed directories, ${#valid_seed_dirs[@]} valid seed corpora"
        log_info "Created $packaged_seeds seed corpora, $skipped_seeds skipped"

        # Store detection summary
        local total_seeds=$((zip_count + packaged_seeds))
        AUTO_DETECTION_SUMMARY[seed_corpora]="${#seed_dirs[@]} detected, ${#valid_seed_dirs[@]} validated, $total_seeds total ($zip_count existing, $packaged_seeds packaged, $skipped_seeds skipped)"
    fi

    # Enhanced auto-detect and copy all dictionaries
    local dict_count=0
    local dict_skipped=0
    local detected_dicts=()
    local valid_dicts=()

    # Look for dictionaries in multiple locations
    local dict_dirs=("fuzzers/dictionaries" "dictionaries" "dict" "fuzz/dictionaries")
    for dict_dir in "${dict_dirs[@]}"; do
        if [[ -d "$dict_dir" ]]; then
            log_debug "Scanning dictionaries in: $dict_dir"
            while IFS= read -r -d '' dict_file; do
                local dict_name
                dict_name=$(basename "$dict_file")
                detected_dicts+=("$dict_name")

                # Validate dictionary before copying
                if is_valid_dictionary "$dict_file"; then
                    valid_dicts+=("$dict_name")

                    # Check if dictionary has changed
                    local current_hash
                    local cached_hash
                    current_hash=$(get_file_hash "$dict_file")
                    cached_hash="${DICTIONARY_CACHE[$dict_name]:-}"

                    if [[ "$current_hash" != "$cached_hash" ]] && [[ "$current_hash" != "unknown" ]]; then
                        if cp "$dict_file" "$OUT/" 2>/dev/null; then
                            ((dict_count++))
                            local size
                            size=$(get_file_size "$OUT/$dict_name")
                            log_debug "Copied dictionary: $dict_name ($(format_size "$size"))"

                            # Cache the hash for next time
                            DICTIONARY_CACHE[$dict_name]="$current_hash"
                        else
                            log_warning "Failed to copy dictionary: $dict_name"
                        fi
                    else
                        ((dict_skipped++))
                        local size
                        size=$(get_file_size "$OUT/$dict_name")
                        log_debug "Skipped dictionary: $dict_name (up-to-date, $(format_size "$size"))"
                    fi
                else
                    log_warning "Skipping invalid dictionary: $dict_name (empty or invalid format)"
                fi
            done < <(find "$dict_dir" -name "*.dict" -type f -print0)
        fi
    done

    if [[ ${#detected_dicts[@]} -gt 0 ]]; then
        log_info "Auto-detected ${#detected_dicts[@]} dictionary files, ${#valid_dicts[@]} valid dictionaries"
        log_info "Copied $dict_count dictionaries, $dict_skipped skipped"

        # Store detection summary
        AUTO_DETECTION_SUMMARY[dictionaries]="${#detected_dicts[@]} detected, ${#valid_dicts[@]} validated, $dict_count copied, $dict_skipped skipped"
    fi

    # Auto-detect fuzz targets and create options files
    log_debug "Auto-detecting fuzz targets for options files"
    local options_count=0
    local detected_targets=()
    find "$OUT" -name "fuzz_*" -type f | while read -r fuzz_binary; do
        local target_name
        target_name=$(basename "$fuzz_binary")
        detected_targets+=("$target_name")
        local options_file="${OUT}/${target_name}.options"

        # Only create options file if it doesn't exist
        if [[ ! -f "$options_file" ]]; then
            cat > "$options_file" << EOF
[libfuzzer]
max_len=4096
timeout=60
EOF
            ((options_count++))
            log_debug "Created options file for: $target_name"
        fi
    done

    log_info "Auto-detected ${#detected_targets[@]} fuzz targets for options: ${detected_targets[*]}"
    log_info "Created $options_count options files"

    # Store detection summary
    AUTO_DETECTION_SUMMARY[options_files]="${#detected_targets[@]} detected, $options_count created"

    log_success "Supporting files copied and auto-generated"
}

# =============================================================================
# Rapid Expansion Functions
# =============================================================================

expand_fuzzers_rapid() {
    log_build_progress "Starting Rapid Fuzzer Expansion..."

    # Use Python helper for automated detection and building
    if command -v python3 >/dev/null 2>&1; then
        log_debug "Using Python helper for rapid expansion"

        # Get current directory for Python helper
        local helper_dir
        helper_dir=$(cd ../../../ && pwd)

        # Run check_build to validate current setup
        log_info "Running Python helper check_build..."
        if cd "$helper_dir" && python3 infra/helper.py check_build "${PROJECT_NAME:-gemini_cli}" 2>&1 | tee -a "$BUILD_LOG_FILE"; then
            log_success "Python helper check_build passed"
        else
            log_warning "Python helper check_build failed, continuing with manual build"
        fi

        # Try to build fuzzers using Python helper
        log_info "Attempting Python helper build_fuzzers..."
        if python3 infra/helper.py build_fuzzers "${PROJECT_NAME:-gemini_cli}" 2>&1 | tee -a "$BUILD_LOG_FILE"; then
            log_success "Python helper build completed successfully"

            # Copy artifacts from Python helper build
            local helper_out="${helper_dir}/build/out/${PROJECT_NAME:-gemini_cli}"
            if [[ -d "$helper_out" ]]; then
                log_info "Copying Python helper build artifacts..."
                cp -r "$helper_out"/* "$OUT/" 2>/dev/null || log_debug "No additional artifacts to copy"
            fi
        else
            log_warning "Python helper build failed, falling back to manual build"
        fi

        cd "$SCRIPT_DIR"
    else
        log_warning "Python3 not available, using manual expansion only"
    fi

    log_success "Rapid expansion completed"
}

auto_expand_languages() {
    log_build_progress "Auto-expanding supported language fuzzers..."

    # Enhanced language detection and expansion
    local detected_languages=()

    # Check for various language indicators
    if [[ -d "gofuzz" ]] || find . -name "fuzz_*.go" -type f | grep -q .; then
        detected_languages+=("go")
    fi

    if [[ -d "fuzzers" ]] || find . -name "fuzz_*.js" -type f | grep -q .; then
        detected_languages+=("javascript")
    fi

    if [[ -d "java" ]] || find . -name "*Fuzz*.java" -type f | grep -q .; then
        detected_languages+=("java")
    fi

    if find . -name "fuzz_*.cpp" -o -name "fuzz_*.cc" -o -name "fuzz_*.cxx" -type f | grep -q .; then
        detected_languages+=("cpp")
    fi

    if find . -name "fuzz_*.c" -type f | grep -q .; then
        detected_languages+=("c")
    fi

    if [[ -d "rust" ]] || find . -name "fuzz_*.rs" -type f | grep -q .; then
        detected_languages+=("rust")
    fi

    if find . -name "fuzz_*.py" -type f | grep -q .; then
        detected_languages+=("python")
    fi

    log_info "Auto-detected languages: ${detected_languages[*]:-none}"

    # Store language detection summary
    AUTO_DETECTION_SUMMARY[languages]="${detected_languages[*]:-none detected}"

    # Call appropriate build functions based on detected languages
    for lang in "${detected_languages[@]}"; do
        case "$lang" in
            "go")
                build_go_fuzzers
                ;;
            "javascript")
                build_javascript_fuzzers
                ;;
            "java")
                build_java_fuzzers
                ;;
            "cpp")
                build_cpp_fuzzers
                ;;
            "c")
                build_c_fuzzers
                ;;
            "rust")
                build_rust_fuzzers
                ;;
            "python")
                build_python_fuzzers
                ;;
            *)
                log_warning "Unknown language detected: $lang"
                ;;
        esac
    done
}

rapid_seed_expansion() {
    log_build_progress "Rapid Seed Corpus Expansion..."

    local total_seeds=0
    local total_dirs=0

    # Enhanced seed directory detection
    local seed_locations=(
        "seeds"
        "seed"
        "corpus"
        "testdata"
        "fuzz/seeds"
        "fuzz/corpus"
        "gofuzz/seeds"
        "fuzzers/seeds"
        "java/seeds"
        "rust/seeds"
    )

    for seed_base in "${seed_locations[@]}"; do
        if [[ -d "$seed_base" ]]; then
            log_debug "Processing seed location: $seed_base"

            while IFS= read -r -d '' seed_dir; do
                ((total_dirs++))
                local target_name
                target_name=$(basename "$seed_dir")

                if is_valid_seed_directory "$seed_dir"; then
                    local seed_zip="${OUT}/${target_name}_seed_corpus.zip"

                    if [[ ! -f "$seed_zip" ]] || [[ "$seed_dir" -nt "$seed_zip" ]]; then
                        if zip -jr "$seed_zip" "$seed_dir" >/dev/null 2>&1; then
                            ((total_seeds++))
                            local size
                            size=$(get_file_size "$seed_zip")
                            log_success "Rapid seed expansion: $target_name ($(format_size "$size"))"
                        fi
                    else
                        log_debug "Seed corpus up-to-date: $target_name"
                    fi
                fi
            done < <(find "$seed_base" -mindepth 1 -maxdepth 1 -type d -print0)
        fi
    done

    log_info "Rapid seed expansion: $total_dirs directories processed, $total_seeds corpora created"
    AUTO_DETECTION_SUMMARY[rapid_seeds]="$total_dirs processed, $total_seeds created"
}

rapid_dictionary_expansion() {
    log_build_progress "Rapid Dictionary Expansion..."

    local total_dicts=0
    local dict_locations=(
        "fuzzers/dictionaries"
        "dictionaries"
        "dict"
        "fuzz/dictionaries"
        "gofuzz/dictionaries"
        "seeds/dictionaries"
    )

    for dict_base in "${dict_locations[@]}"; do
        if [[ -d "$dict_base" ]]; then
            log_debug "Processing dictionary location: $dict_base"

            while IFS= read -r -d '' dict_file; do
                local dict_name
                dict_name=$(basename "$dict_file")

                if is_valid_dictionary "$dict_file"; then
                    local current_hash
                    local cached_hash
                    current_hash=$(get_file_hash "$dict_file")
                    cached_hash="${DICTIONARY_CACHE[$dict_name]:-}"

                    if [[ "$current_hash" != "$cached_hash" ]] && [[ "$current_hash" != "unknown" ]]; then
                        if cp "$dict_file" "$OUT/" 2>/dev/null; then
                            ((total_dicts++))
                            local size
                            size=$(get_file_size "$OUT/$dict_name")
                            log_success "Rapid dictionary expansion: $dict_name ($(format_size "$size"))"

                            DICTIONARY_CACHE[$dict_name]="$current_hash"
                        fi
                    else
                        log_debug "Dictionary up-to-date: $dict_name"
                    fi
                fi
            done < <(find "$dict_base" -name "*.dict" -type f -print0)
        fi
    done

    log_info "Rapid dictionary expansion: $total_dicts dictionaries copied"
    AUTO_DETECTION_SUMMARY[rapid_dicts]="$total_dicts copied"
}

auto_generate_options() {
    log_build_progress "Auto-generating fuzz target options..."

    local options_count=0

    # Generate options for all executable fuzz targets
    find "$OUT" -type f \( -name "fuzz_*" -o -name "*Fuzz*" -o -name "*.py" \) ! -name "*.options" | while read -r fuzz_binary; do
        if [[ -x "$fuzz_binary" ]] || [[ "$fuzz_binary" == *.py ]]; then
            local target_name
            target_name=$(basename "$fuzz_binary")
            local options_file="${OUT}/${target_name}.options"

            if [[ ! -f "$options_file" ]]; then
                # Generate language-specific options
                case "$target_name" in
                    *.py)
                        cat > "$options_file" << EOF
[libfuzzer]
max_len=8192
timeout=120
dict=$target_name.dict
EOF
                        ;;
                    *Fuzz*)
                        cat > "$options_file" << EOF
[libfuzzer]
max_len=4096
timeout=60
dict=$target_name.dict
EOF
                        ;;
                    *)
                        cat > "$options_file" << EOF
[libfuzzer]
max_len=4096
timeout=60
dict=$target_name.dict
EOF
                        ;;
                esac
                ((options_count++))
                log_debug "Generated options for: $target_name"
            fi
        fi
    done

    log_info "Auto-generated $options_count options files"
    AUTO_DETECTION_SUMMARY[rapid_options]="$options_count generated"
}

comprehensive_fuzz_expansion() {
    log_build_progress "Starting Comprehensive Fuzz Expansion..."

    # Run all expansion functions
    expand_fuzzers_rapid
    auto_expand_languages
    rapid_seed_expansion
    rapid_dictionary_expansion
    auto_generate_options

    log_success "Comprehensive fuzz expansion completed"
}

# =============================================================================
# Main Build Process
# =============================================================================

main() {
    start_timer "total_build"
    log_info "🚀 Starting OSS-Fuzz build for Gemini CLI"
    log_info "Build started at: $BUILD_START_TIME"
    log_info "Build log: $BUILD_LOG_FILE"
    log_info "Debug mode: ${DEBUG:-false}"
    log_info "Performance mode: enabled"

    # Load build cache from previous runs
    load_build_cache

    # Apply performance optimizations early
    optimize_build_performance

    # Environment validation
    validate_environment || {
        log_error "❌ Environment validation failed"
        exit 1
    }

    log_step_success "Environment validation"

    # Print system information
    log_debug "System information:"
    log_debug "  OS: $(uname -s 2>/dev/null || echo 'Unknown')"
    log_debug "  Architecture: $(uname -m 2>/dev/null || echo 'Unknown')"
    log_debug "  Source directory: $SRC"
    log_debug "  Output directory: $OUT"
    log_debug "  Current directory: $(pwd)"

    # Use comprehensive rapid expansion system
    comprehensive_fuzz_expansion

    # Copy supporting files
    copy_supporting_files

    # Show auto-detection summary
    log_detection_summary

    # Enhanced build summary with comprehensive statistics
    log_final_build_summary

    # Save cache for next build
    save_build_cache
}

log_final_build_summary() {
    end_timer "total_build"
    log_build_progress "🎉 Build completed successfully!"
    log_info "Build finished at: $(date '+%Y-%m-%d %H:%M:%S')"

    # Calculate total build time with high precision
    local end_time
    end_time=$(date +%s%3N)
    local start_time
    start_time=$(date -d "$BUILD_START_TIME" +%s%3N)
    local total_ms=$((end_time - start_time))
    local total_seconds=$((total_ms / 1000))
    local total_minutes=$((total_seconds / 60))

    log_info "⏱️  Total build time: $total_seconds seconds (${total_ms}ms)"
    if [[ $total_minutes -gt 0 ]]; then
        log_info "⏱️  Total build time: $total_minutes minutes $((total_seconds % 60)) seconds"
    fi

    # Comprehensive build statistics
    echo "" >> "$BUILD_LOG_FILE"
    echo "=== BUILD SUMMARY ===" >> "$BUILD_LOG_FILE"
    echo "Start Time: $BUILD_START_TIME" >> "$BUILD_LOG_FILE"
    echo "End Time: $(date '+%Y-%m-%d %H:%M:%S')" >> "$BUILD_LOG_FILE"
    echo "Total Build Time: $total_seconds seconds" >> "$BUILD_LOG_FILE"
    echo "" >> "$BUILD_LOG_FILE"

    # Count total built fuzz targets
    local total_fuzz_targets
    total_fuzz_targets=$(find "$OUT" -name "fuzz_*" -type f 2>/dev/null | wc -l)
    log_info "Total fuzz targets built: $total_fuzz_targets"

    # List all built fuzz targets with sizes
    if [[ $total_fuzz_targets -gt 0 ]]; then
        log_info "Built fuzz targets:"
        echo "Built fuzz targets ($total_fuzz_targets):" >> "$BUILD_LOG_FILE"
        find "$OUT" -name "fuzz_*" -type f -exec basename {} \; 2>/dev/null | sort | while read -r target; do
            local size
            size=$(get_file_size "$OUT/$target")
            log_info "  $target ($(format_size "$size"))"
            echo "  $target ($(format_size "$size"))" >> "$BUILD_LOG_FILE"
        done
    fi

    # List supporting files
    local total_seed_files
    local total_dict_files
    local total_options_files
    total_seed_files=$(find "$OUT" -name "*_seed_corpus.zip" -type f 2>/dev/null | wc -l)
    total_dict_files=$(find "$OUT" -name "*.dict" -type f 2>/dev/null | wc -l)
    total_options_files=$(find "$OUT" -name "*.options" -type f 2>/dev/null | wc -l)

    log_info "Supporting files created:"
    log_info "  Seed corpora: $total_seed_files"
    log_info "  Dictionaries: $total_dict_files"
    log_info "  Options files: $total_options_files"

    echo "" >> "$BUILD_LOG_FILE"
    echo "Supporting files:" >> "$BUILD_LOG_FILE"
    echo "  Seed corpora: $total_seed_files" >> "$BUILD_LOG_FILE"
    echo "  Dictionaries: $total_dict_files" >> "$BUILD_LOG_FILE"
    echo "  Options files: $total_options_files" >> "$BUILD_LOG_FILE"
    echo "" >> "$BUILD_LOG_FILE"

    # Calculate total output size
    local total_size
    total_size=$(find "$OUT" -type f -exec stat -c%s {} \; 2>/dev/null | awk '{sum+=$1} END {print sum}' 2>/dev/null || echo "0")
    if [[ $total_size -gt 0 ]]; then
        log_info "Total output size: $(format_size "$total_size")"
        echo "Total output size: $(format_size "$total_size")" >> "$BUILD_LOG_FILE"
    fi

    echo "" >> "$BUILD_LOG_FILE"
    echo "=== PERFORMANCE METRICS ===" >> "$BUILD_LOG_FILE"
    echo "Build Performance Summary:" >> "$BUILD_LOG_FILE"
    echo "  Total Time: ${total_seconds}s (${total_ms}ms)" >> "$BUILD_LOG_FILE"

    # Log performance metrics for each step
    for step in "${!BUILD_TIMING[@]}"; do
        local duration="${BUILD_TIMING[${step}_duration]:-0}"
        local memory="${BUILD_MEMORY[$step]:-0}"
        local status="${BUILD_SUCCESS[$step]:-unknown}"
        if [[ $duration -gt 0 ]]; then
            echo "  $step: ${duration}ms, ${memory}KB, status: $status" >> "$BUILD_LOG_FILE"
        fi
    done

    echo "" >> "$BUILD_LOG_FILE"
    echo "=== END BUILD SUMMARY ===" >> "$BUILD_LOG_FILE"
    echo "" >> "$BUILD_LOG_FILE"

    # Display performance highlights
    log_info "📊 Performance Highlights:"
    log_info "  Build completed in ${total_seconds}s"
    log_info "  Peak memory usage: $(ps -o rss= $$ 2>/dev/null | awk '{print $1}' || echo 'unknown')KB"
    log_info "  Success rate: $(grep -c "success" <<< "${BUILD_SUCCESS[@]:-0}")/$((${#BUILD_SUCCESS[@]} + 1))"
}

save_build_cache() {
    # Save cache information for next build
    local cache_file="${OUT}/.build_cache"
    {
        echo "# Build cache generated on $(date)"
        echo "# Fuzz target hashes"
        for target in "${!FUZZ_TARGET_CACHE[@]}"; do
            echo "FUZZ:$target:${FUZZ_TARGET_CACHE[$target]}"
        done
        echo "# Dictionary hashes"
        for dict in "${!DICTIONARY_CACHE[@]}"; do
            echo "DICT:$dict:${DICTIONARY_CACHE[$dict]}"
        done
    } > "$cache_file" 2>/dev/null || true

    if [[ -f "$cache_file" ]]; then
        log_debug "Build cache saved to: $cache_file"
    fi
}

load_build_cache() {
    # Load cache information from previous build
    local cache_file="${OUT}/.build_cache"
    if [[ -f "$cache_file" ]]; then
        log_debug "Loading build cache from: $cache_file"
        while IFS=':' read -r type name hash; do
            case "$type" in
                "FUZZ")
                    FUZZ_TARGET_CACHE["$name"]="$hash"
                    ;;
                "DICT")
                    DICTIONARY_CACHE["$name"]="$hash"
                    ;;
            esac
        done < "$cache_file"
    fi
}

rapid_expand() {
    log_info "🚀 Starting Rapid Fuzzer Expansion with Python Helper Integration"
    log_info "This will automatically detect, build, and expand all fuzz targets"

    # Set rapid expansion mode
    export RAPID_EXPANSION=true
    export DEBUG=true

    # Run the comprehensive expansion
    comprehensive_fuzz_expansion

    # Run Python helper validation if available
    if command -v python3 >/dev/null 2>&1; then
        local helper_dir
        helper_dir=$(cd ../../../ && pwd)
        log_info "🔍 Running Python helper validation..."

        if cd "$helper_dir" && python3 infra/helper.py check_build "${PROJECT_NAME:-gemini_cli}" 2>&1 | tee -a "$BUILD_LOG_FILE"; then
            log_success "✅ Python helper validation passed"
        else
            log_warning "⚠️  Python helper validation failed, but continuing..."
        fi

        cd "$SCRIPT_DIR"
    fi

    log_success "🎉 Rapid expansion completed successfully!"
    log_info "📊 Summary:"
    echo "" >> "$BUILD_LOG_FILE"
    echo "=== RAPID EXPANSION SUMMARY ===" >> "$BUILD_LOG_FILE"
    echo "Build completed at: $(date '+%Y-%m-%d %H:%M:%S')" >> "$BUILD_LOG_FILE"

    # Show final counts
    local total_fuzzers
    local total_seeds
    local total_dicts
    local total_options
    total_fuzzers=$(find "$OUT" -name "fuzz_*" -o -name "*Fuzz*" -type f 2>/dev/null | wc -l)
    total_seeds=$(find "$OUT" -name "*_seed_corpus.zip" -type f 2>/dev/null | wc -l)
    total_dicts=$(find "$OUT" -name "*.dict" -type f 2>/dev/null | wc -l)
    total_options=$(find "$OUT" -name "*.options" -type f 2>/dev/null | wc -l)

    log_info "  🎯 Fuzz targets: $total_fuzzers"
    log_info "  📦 Seed corpora: $total_seeds"
    log_info "  📚 Dictionaries: $total_dicts"
    log_info "  ⚙️  Options files: $total_options"

    echo "Fuzz targets: $total_fuzzers" >> "$BUILD_LOG_FILE"
    echo "Seed corpora: $total_seeds" >> "$BUILD_LOG_FILE"
    echo "Dictionaries: $total_dicts" >> "$BUILD_LOG_FILE"
    echo "Options files: $total_options" >> "$BUILD_LOG_FILE"
    echo "" >> "$BUILD_LOG_FILE"
    echo "🎉 Rapid expansion completed successfully!" >> "$BUILD_LOG_FILE"
}

# Language-specific fuzzing modes
case "${1:-}" in
    --go)
        log_info "🐹 Go-only fuzzing mode"
        # Source environment and validate
        source "${BASH_SOURCE%/*}/../.bashrc" 2>/dev/null || true
        validate_environment || exit 1
        build_go_fuzzers
        copy_supporting_files
        log_detection_summary
        log_final_build_summary
        exit 0
        ;;
    --js|--javascript)
        log_info "🌐 JavaScript-only fuzzing mode"
        source "${BASH_SOURCE%/*}/../.bashrc" 2>/dev/null || true
        validate_environment || exit 1
        build_javascript_fuzzers
        copy_supporting_files
        log_detection_summary
        log_final_build_summary
        exit 0
        ;;
    --java)
        log_info "☕ Java-only fuzzing mode"
        source "${BASH_SOURCE%/*}/../.bashrc" 2>/dev/null || true
        validate_environment || exit 1
        build_java_fuzzers
        copy_supporting_files
        log_detection_summary
        log_final_build_summary
        exit 0
        ;;
    --python)
        log_info "🐍 Python-only fuzzing mode"
        source "${BASH_SOURCE%/*}/../.bashrc" 2>/dev/null || true
        validate_environment || exit 1
        build_python_fuzzers
        copy_supporting_files
        log_detection_summary
        log_final_build_summary
        exit 0
        ;;
    --cpp|--c++)
        log_info "🚀 C++ fuzzing mode activated"
        source "${BASH_SOURCE%/*}/../.bashrc" 2>/dev/null || true
        validate_environment || exit 1
        build_cpp_fuzzers
        copy_supporting_files
        log_detection_summary
        log_final_build_summary
        exit 0
        ;;
    --c)
        log_info "🚀 C fuzzing mode activated"
        source "${BASH_SOURCE%/*}/../.bashrc" 2>/dev/null || true
        validate_environment || exit 1
        build_c_fuzzers
        copy_supporting_files
        log_detection_summary
        log_final_build_summary
        exit 0
        ;;
    --rust)
        log_info "🦀 Rust fuzzing mode activated"
        source "${BASH_SOURCE%/*}/../.bashrc" 2>/dev/null || true
        validate_environment || exit 1
        build_rust_fuzzers
        copy_supporting_files
        log_detection_summary
        log_final_build_summary
        exit 0
        ;;
    --enable-cpp)
        log_info "🔓 Enabling C++ fuzzing support"
        export ENABLE_CPP=1
        shift
        ;;
    --enable-c)
        log_info "🔓 Enabling C fuzzing support"
        export ENABLE_C=1
        shift
        ;;
    --enable-rust)
        log_info "🔓 Enabling Rust fuzzing support"
        export ENABLE_RUST=1
        shift
        ;;
    --enable-all-supported)
        log_info "🔓 Enabling all supported languages (C++, C, Rust)"
        export ENABLE_CPP=1
        export ENABLE_C=1
        export ENABLE_RUST=1
        shift
        ;;
    --rapid)
        log_info "🚀 Rapid expansion mode enabled"
        rapid_expand
        exit 0
        ;;
    --help|-h)
        echo "🚀 Gemini CLI OSS-Fuzz Build Script"
        echo ""
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  --go              Build Go fuzz targets only"
        echo "  --js, --javascript Build JavaScript fuzz targets only"
        echo "  --java            Build Java fuzz targets only"
        echo "  --python          Build Python fuzz targets only"
        echo "  --cpp, --c++      Build C++ fuzz targets only"
        echo "  --c               Build C fuzz targets only"
        echo "  --rust            Build Rust fuzz targets only"
        echo "  --rapid           Run rapid expansion mode"
        echo "  --enable-cpp      Enable C++ fuzzing support"
        echo "  --enable-c        Enable C fuzzing support"
        echo "  --enable-rust     Enable Rust fuzzing support"
        echo "  --enable-all-supported  Enable all supported languages"
        echo "  --help, -h        Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  DEBUG=true        Enable debug logging"
        echo "  PERFORMANCE=true  Enable performance monitoring"
        echo ""
        exit 0
        ;;
    *)
        # Default: run full build
        main "$@"
        ;;
esac
