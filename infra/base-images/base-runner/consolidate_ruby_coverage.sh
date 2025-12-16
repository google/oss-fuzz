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
#
# Consolidates SimpleCov HTML reports into standalone HTML files.
#
# This script creates standalone HTML files with all assets inlined (CSS, JS, images)
# for easy distribution and viewing without a web server.
#
# Usage: consolidate_ruby_coverage.sh
#
# Environment variables required:
#   REPORT_PLATFORM_DIR - Directory containing Ruby coverage HTML report
#
################################################################################

set -e

echo "Creating standalone HTML report..."

# Create standalone HTML file by inlining all assets
if [ -f "$REPORT_PLATFORM_DIR/index.html" ]; then
  python3 /usr/local/bin/consolidate_html.py \
    "$REPORT_PLATFORM_DIR/index.html" \
    "$REPORT_PLATFORM_DIR/standalone.html"
  
  echo "Standalone report created at $REPORT_PLATFORM_DIR/standalone.html"
else
  echo "Warning: No index.html found at $REPORT_PLATFORM_DIR"
fi

set +e
