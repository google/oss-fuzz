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

export RUSTFLAGS=""
python3 -m pip install -U hatch
python3 -m pip uninstall -y libcst
python3 -m pip install .

# Change directory to force pyinstaller to load in the package we build
cd ../
mkdir fuzzbuild
cd fuzzbuild

if [ "$SANITIZER" = "address" ]
then
  # Enable pysecsan
  export ENABLE_PYSECSAN="1"
fi

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done
