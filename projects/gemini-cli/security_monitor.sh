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

# Quick security check for Gemini CLI OSS-Fuzz
set -euo pipefail

echo "🔒 Security Check - Gemini CLI OSS-Fuzz"

# Check critical security issues
issues=0

# No unverified downloads
if grep -r "curl.*-O\|wget.*-O" . --exclude-dir=.git 2>/dev/null | grep -v "sha256sum" >/dev/null; then
    echo "❌ Unverified downloads detected"
    issues=$((issues + 1))
fi

# No sudo usage (excluding security validation patterns)
if find . -name "*.sh" 2>/dev/null | xargs grep -l "sudo" 2>/dev/null | grep -v "continuous_compliance.sh" | grep -v "security_monitor.sh" >/dev/null; then
    echo "❌ Sudo usage detected"
    issues=$((issues + 1))
fi

# Dependencies pinned
if [ -f "gofuzz/go.mod" ] && grep -q "@latest\|@master" gofuzz/go.mod; then
    echo "❌ Unpinned dependencies"
    issues=$((issues + 1))
fi

# No hardcoded tokens (excluding security validation patterns)
if grep -r "PERSONAL_ACCESS_TOKEN\|GITHUB_TOKEN\|API_KEY" . --exclude-dir=.git 2>/dev/null | grep -v "example\|test\|fuzz_.*\.go\|security.*validation\|blockedCommands\|dangerous.*patterns" >/dev/null; then
    echo "❌ Hardcoded tokens detected"
    issues=$((issues + 1))
fi

# Fuzzer security validation
security_checks=$(grep -r "SecurityViolation\|security.*check" gofuzz/fuzz/ 2>/dev/null | wc -l)
if [ $security_checks -lt 10 ]; then
    echo "❌ Insufficient security validation"
    issues=$((issues + 1))
fi

if [ $issues -eq 0 ]; then
    echo "✅ All security checks passed"
    exit 0
else
    echo "❌ $issues security issues found"
    exit 1
fi
