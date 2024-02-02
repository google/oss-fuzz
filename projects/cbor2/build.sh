# Copyright 2024 Google LLC
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

# Ensure C extension gets built
export CBOR2_BUILD_C_EXTENSION=1

# Build and install project (using current CFLAGS, CXXFLAGS). This is required
# for projects with C extensions so that they're built with the proper flags.
pip3 install .

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
    compile_python_fuzzer $fuzzer
done
