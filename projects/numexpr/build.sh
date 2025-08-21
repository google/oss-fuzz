#!/bin/bash -eu

# Copyright 2023 Google LLC
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
##########################################################################

# Fix the pyproject.toml issue by specifying the license correctly
sed -i 's/license = "MIT"/license = {text = "MIT"}/' /src/numexpr/pyproject.toml

python3 -m pip install -r /src/numexpr/requirements.txt
python3 /src/numexpr/setup.py build install

# Build fuzzers in $OUT.
for fuzzer in $(find /src -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done
