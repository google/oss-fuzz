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

# Build and install project. The Rust extension is built via setuptools-rust.
# Unset RUSTFLAGS because OSS-Fuzz sanitizer flags (e.g. -Zsanitizer=address)
# are incompatible with proc-macro crates. Fuzzing happens at the Python level
# via atheris, so Rust code does not need sanitizer instrumentation.
RUSTFLAGS="" pip3 install .

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
    compile_python_fuzzer $fuzzer
done
