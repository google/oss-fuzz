#!/bin/bash -eu
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

# Define a variable for the repeated path
SECRETS_SAFE_PATH="$SRC/ps-integration-ansible/beyondtrust/secrets_safe"

# Install Python dependencies from the mounted requirements.txt file
pip install --upgrade pip
pip install -r "$SECRETS_SAFE_PATH/requirements.txt"

# Compile the fuzz target
python3 -m compileall "$SECRETS_SAFE_PATH/fuzz_secrets_safe_lookup.py"

# Move the fuzz target to the output directory
cp "$SECRETS_SAFE_PATH/fuzz_secrets_safe_lookup.py" "$OUT/fuzz_secrets_safe_lookup"