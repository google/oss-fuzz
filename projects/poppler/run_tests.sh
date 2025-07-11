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

PROJECT_SRC_DIR="/src/poppler"

echo "==> Changing to Poppler source directory: $PROJECT_SRC_DIR"
cd "$PROJECT_SRC_DIR"

echo "==> Setup needed right now..."  # DO NOT SUBMIT
cmake .
make
echo "==> Setup finished successfully."  # DO NOT SUBMIT

# No test data found in $testdatadir.
# You will not be able to run 'make test' successfully.

# The test data is not included in the source packages
# and is also not part of the main git repository. Instead,
# you can checkout the test data from its own git
# repository with:

#   git clone git://git.freedesktop.org/git/poppler/test

# You should checkout the test data as a sibling of your
# poppler source folder or specify the location of your
# checkout with -DTESTDATADIR=/path/to/checkoutdir/test.

echo "==> Running all tests..."
make test
echo "==> Test run finished successfully."