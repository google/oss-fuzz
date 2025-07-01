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

PROJECT_SRC_DIR="$SRC/keystone"

echo "==> Changing to Keystone source directory: $PROJECT_SRC_DIR"
cd "$PROJECT_SRC_DIR"

echo "==> Setup needed right now..."  # DO NOT SUBMIT
cmake .
make
echo "==> Setup finished successfully."  # DO NOT SUBMIT

# clang++: error: linker command failed with exit code 1 (use -v to see invocation)
# make[2]: *** [kstool/CMakeFiles/kstool.dir/build.make:98: kstool/kstool] Error 1
# make[1]: *** [CMakeFiles/Makefile2:518: kstool/CMakeFiles/kstool.dir/all] Error 2

echo "==> Running all tests..."
make check
echo "==> Test run finished successfully."
