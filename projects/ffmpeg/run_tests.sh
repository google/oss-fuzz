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

# Usage: bash run_test.sh 
# Runs all tests.

set -e # Exit immediately if any command fails

PROJECT_SRC_DIR="$SRC/ffmpeg"

echo "==> Changing to FFmpeg source directory: $PROJECT_SRC_DIR"
cd "$PROJECT_SRC_DIR"

echo "==> Running all FATE tests..."
make fate
echo "==> Test run finished successfully."
