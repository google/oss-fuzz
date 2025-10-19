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

# Build script for OSS-Fuzz

# Navigate to project directory
cd $SRC/device-fingerprinting-pro

# Install the package
pip3 install -e .

# Build fuzz targets
for fuzzer in fuzz/fuzz_*.py; do
  fuzzer_basename=$(basename -s .py $fuzzer)
  
  # Compile with atheris - package discovery is handled automatically after pip install
  compile_python_fuzzer $fuzzer
done

# Copy seed corpus if available
if [ -d "fuzz/corpus" ]; then
  for fuzzer in fuzz/fuzz_*.py; do
    fuzzer_basename=$(basename -s .py $fuzzer)
    zip -j $OUT/${fuzzer_basename}_seed_corpus.zip fuzz/corpus/${fuzzer_basename}/* || true
  done
fi
