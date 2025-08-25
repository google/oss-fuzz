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
#
################################################################################

set -euo pipefail

# Configuration
PROJECT_NAME="gemini_cli"
OSS_FUZZ_REPO="google/oss-fuzz"
DEPLOYMENT_ENV="${1:-staging}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Pre-deployment checks
pre_deployment_checks() {
    log_info "Running pre-deployment checks..."
    
    # Check if we're in the right directory
    if [[ ! -f "project.yaml" ]]; then
        log_error "project.yaml not found. Please run this script from the project directory."
        exit 1
    fi
    
    # Check for required files
    local required_files=("build.sh" "Dockerfile" "project.yaml")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "Required file $file not found"
            exit 1
        fi
    done
    
    # Check for Google copyright headers
    log_info "Checking Google copyright headers..."
    local files_without_headers=()
    while IFS= read -r -d '' file; do
        if ! head -20 "$file" | grep -q "Copyright 2025 Google LLC"; then
            files_without_headers+=("$file")
        fi
    done < <(find . -name "*.py" -o -name "*.js" -o -name "*.go" -o -name "*.yaml" -o -name "*.yml" -print0)
    
    if [[ ${#files_without_headers[@]} -gt 0 ]]; then
        log_error "Files without Google copyright headers:"
        printf '%s\n' "${files_without_headers[@]}"
        exit 1
    fi
    
    # Check for AI references
    log_info "Checking for AI references..."
    if grep -r -i "ai-powered\|ai-assisted\|sentient core\|tower of babel" . --exclude-dir=node_modules --exclude-dir=.git; then
        log_error "AI references found that need to be removed"
        exit 1
    fi
    
    log_success "Pre-deployment checks passed"
}

# Build and test
build_and_test() {
    log_info "Building and testing fuzzers..."
    
    # Make build script executable
    chmod +x build.sh
    
    # Test build script
    if ! ./build.sh; then
        log_error "Build script failed"
        exit 1
    fi
    
    # Test Docker build
    if ! docker build -t "${PROJECT_NAME}-test" .; then
        log_error "Docker build failed"
        exit 1
    fi
    
    log_success "Build and test completed successfully"
}

# Deploy to OSS-Fuzz
deploy_to_oss_fuzz() {
    log_info "Deploying to OSS-Fuzz ($DEPLOYMENT_ENV)..."
    
    # Clone OSS-Fuzz repository if not exists
    if [[ ! -d "../oss-fuzz" ]]; then
        log_info "Cloning OSS-Fuzz repository..."
        git clone "https://github.com/${OSS_FUZZ_REPO}.git" ../oss-fuzz
    fi
    
    # Navigate to OSS-Fuzz directory
    cd ../oss-fuzz
    
    # Create or update project directory
    if [[ ! -d "projects/${PROJECT_NAME}" ]]; then
        log_info "Creating project directory..."
        mkdir -p "projects/${PROJECT_NAME}"
    fi
    
    # Copy project files
    log_info "Copying project files..."
    cp -r "../${PROJECT_NAME}/"* "projects/${PROJECT_NAME}/"
    
    # Commit changes
    git add "projects/${PROJECT_NAME}/"
    
    if git diff --staged --quiet; then
        log_warning "No changes to commit"
        return 0
    fi
    
    git commit -m "Deploy ${PROJECT_NAME} to OSS-Fuzz (${DEPLOYMENT_ENV})"
    
    # Push changes
    if [[ "$DEPLOYMENT_ENV" == "production" ]]; then
        log_info "Pushing to production..."
        git push origin main
    else
        log_info "Pushing to staging branch..."
        git push origin "staging-${PROJECT_NAME}"
    fi
    
    log_success "Deployment completed"
}

# Post-deployment verification
post_deployment_verification() {
    log_info "Running post-deployment verification..."
    
    # Wait for OSS-Fuzz to pick up changes
    sleep 30
    
    # Check if project is visible in OSS-Fuzz
    log_info "Verifying project visibility..."
    
    # You can add more verification steps here
    # For example, checking the OSS-Fuzz dashboard or API
    
    log_success "Post-deployment verification completed"
}

# Main deployment function
main() {
    log_info "Starting automated deployment for ${PROJECT_NAME} to ${DEPLOYMENT_ENV}"
    
    # Store current directory
    local current_dir=$(pwd)
    
    # Run deployment steps
    pre_deployment_checks
    build_and_test
    deploy_to_oss_fuzz
    post_deployment_verification
    
    log_success "Deployment completed successfully!"
    log_info "Project: ${PROJECT_NAME}"
    log_info "Environment: ${DEPLOYMENT_ENV}"
    log_info "OSS-Fuzz Repository: ${OSS_FUZZ_REPO}"
}

# Help function
show_help() {
    echo "Usage: $0 [staging|production]"
    echo ""
    echo "Deploy the ${PROJECT_NAME} project to OSS-Fuzz"
    echo ""
    echo "Arguments:"
    echo "  staging     Deploy to staging environment (default)"
    echo "  production  Deploy to production environment"
    echo ""
    echo "Examples:"
    echo "  $0 staging"
    echo "  $0 production"
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    staging|production)
        DEPLOYMENT_ENV="$1"
        ;;
    "")
        DEPLOYMENT_ENV="staging"
        ;;
    *)
        log_error "Invalid argument: $1"
        show_help
        exit 1
        ;;
esac

# Run main function
main
