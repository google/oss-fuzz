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
MONITORING_INTERVAL="${1:-300}"  # Default 5 minutes
LOG_FILE="rollout-monitor.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Check OSS-Fuzz project status
check_oss_fuzz_status() {
    log_info "Checking OSS-Fuzz project status..."
    
    # Check if project exists in OSS-Fuzz repository
    if curl -s "https://raw.githubusercontent.com/${OSS_FUZZ_REPO}/main/projects/${PROJECT_NAME}/project.yaml" > /dev/null; then
        log_success "Project found in OSS-Fuzz repository"
        return 0
    else
        log_error "Project not found in OSS-Fuzz repository"
        return 1
    fi
}

# Check build status
check_build_status() {
    log_info "Checking build status..."
    
    # This would typically check the OSS-Fuzz build logs
    # For now, we'll simulate this check
    local build_status=$(curl -s "https://oss-fuzz-build-logs.storage.googleapis.com/log-${PROJECT_NAME}.txt" | tail -n 1 || echo "UNKNOWN")
    
    if [[ "$build_status" == *"SUCCESS"* ]]; then
        log_success "Build status: SUCCESS"
        return 0
    elif [[ "$build_status" == *"FAILURE"* ]]; then
        log_error "Build status: FAILURE"
        return 1
    else
        log_warning "Build status: UNKNOWN"
        return 2
    fi
}

# Check fuzzer coverage
check_fuzzer_coverage() {
    log_info "Checking fuzzer coverage..."
    
    # This would typically check the OSS-Fuzz coverage reports
    # For now, we'll simulate this check
    local coverage_url="https://oss-fuzz.com/coverage-report/job/libfuzzer_asan_${PROJECT_NAME}/latest"
    
    if curl -s "$coverage_url" > /dev/null; then
        log_success "Coverage report available"
        return 0
    else
        log_warning "Coverage report not available yet"
        return 1
    fi
}

# Check for new bugs found
check_new_bugs() {
    log_info "Checking for new bugs found..."
    
    # This would typically check the OSS-Fuzz bug tracker
    # For now, we'll simulate this check
    local bugs_url="https://oss-fuzz.com/testcase?project=${PROJECT_NAME}"
    
    if curl -s "$bugs_url" | grep -q "No testcases found"; then
        log_success "No new bugs found"
        return 0
    else
        log_warning "New bugs may have been found - check OSS-Fuzz dashboard"
        return 1
    fi
}

# Generate health report
generate_health_report() {
    local timestamp=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    local report_file="health-report-$(date +%Y%m%d-%H%M%S).json"
    
    log_info "Generating health report..."
    
    cat > "$report_file" << EOF
{
  "timestamp": "$timestamp",
  "project": "$PROJECT_NAME",
  "status": {
    "oss_fuzz_status": "$(check_oss_fuzz_status && echo "OK" || echo "FAILED")",
    "build_status": "$(check_build_status && echo "OK" || echo "FAILED")",
    "coverage_status": "$(check_fuzzer_coverage && echo "OK" || echo "UNKNOWN")",
    "bug_status": "$(check_new_bugs && echo "OK" || echo "WARNING")"
  },
  "metrics": {
    "monitoring_interval_seconds": $MONITORING_INTERVAL,
    "log_file": "$LOG_FILE"
  }
}
EOF
    
    log_success "Health report generated: $report_file"
}

# Send notification
send_notification() {
    local message="$1"
    local level="${2:-info}"
    
    # This would typically send notifications via email, Slack, etc.
    # For now, we'll just log the notification
    log_info "NOTIFICATION [$level]: $message"
    
    # Example: Send to Slack webhook
    # if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
    #     curl -X POST -H 'Content-type: application/json' \
    #          --data "{\"text\":\"[OSS-Fuzz Monitor] $message\"}" \
    #          "$SLACK_WEBHOOK_URL"
    # fi
}

# Main monitoring function
monitor_rollout() {
    log_info "Starting rollout monitoring for $PROJECT_NAME"
    log_info "Monitoring interval: ${MONITORING_INTERVAL} seconds"
    
    local iteration=1
    
    while true; do
        log_info "=== Monitoring iteration $iteration ==="
        
        # Run all checks
        local overall_status=0
        
        check_oss_fuzz_status || overall_status=1
        check_build_status || overall_status=1
        check_fuzzer_coverage || overall_status=1
        check_new_bugs || overall_status=1
        
        # Generate health report
        generate_health_report
        
        # Send notifications based on status
        if [[ $overall_status -eq 0 ]]; then
            log_success "All systems operational"
            if [[ $iteration -eq 1 ]]; then
                send_notification "OSS-Fuzz integration for $PROJECT_NAME is operational" "success"
            fi
        else
            log_error "Issues detected in OSS-Fuzz integration"
            send_notification "Issues detected in OSS-Fuzz integration for $PROJECT_NAME" "error"
        fi
        
        log_info "Waiting ${MONITORING_INTERVAL} seconds before next check..."
        sleep "$MONITORING_INTERVAL"
        
        ((iteration++))
    done
}

# Help function
show_help() {
    echo "Usage: $0 [monitoring_interval_seconds]"
    echo ""
    echo "Monitor the rollout status of ${PROJECT_NAME} in OSS-Fuzz"
    echo ""
    echo "Arguments:"
    echo "  monitoring_interval_seconds  Interval between checks in seconds (default: 300)"
    echo ""
    echo "Examples:"
    echo "  $0 300    # Check every 5 minutes"
    echo "  $0 60     # Check every minute"
    echo ""
    echo "Environment variables:"
    echo "  SLACK_WEBHOOK_URL  Slack webhook URL for notifications (optional)"
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    "")
        MONITORING_INTERVAL=300
        ;;
    *)
        if [[ "$1" =~ ^[0-9]+$ ]]; then
            MONITORING_INTERVAL="$1"
        else
            log_error "Invalid monitoring interval: $1"
            show_help
            exit 1
        fi
        ;;
esac

# Run monitoring
monitor_rollout
