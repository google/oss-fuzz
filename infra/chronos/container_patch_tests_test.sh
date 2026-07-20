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

echo "Starting container patch tests script"

# Ensure dependencies are installed
python3 -m pip install -r /chronos/requirements.txt

# Capture patch, run tests and then diff patches.
python3 /chronos/integrity_validator_run_tests.py diff-patch before
chmod +x /src/run_tests.sh
/src/run_tests.sh        
python3 /chronos/integrity_validator_run_tests.py diff-patch after