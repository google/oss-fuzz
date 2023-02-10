#!/bin/bash -eu
# Copyright 2022 Google LLC
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

# Avoid build check as it does not work with sanitizers
sed -i 's/def basic_check_build/def basic_check_build():\n    return\ndef basic_check_build2/g' ./sklearn/_build_utils/pre_build_helpers.py

# Include openmp header dirs
export CFLAGS="${CFLAGS} -I/usr/lib/llvm-10/include/openmp/"
export CXXFLAGS="${CXXFLAGS} /usr/lib/llvm-10/include/openmp/"

python3 setup.py install
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  # Add some hidden imports
  compile_python_fuzzer $fuzzer --hidden-import=joblib --hidden-import=threadpoolctl
done
