#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cd $SRC/onnx

# Build ONNX's own protobuf from source so it is compiled with -fPIC,
# which is required to link into the Python extension .so.
# Point FetchContent at pre-downloaded sources so cmake needs no network access.
export CMAKE_ARGS="-DONNX_BUILD_CUSTOM_PROTOBUF=ON \
    -DFETCHCONTENT_SOURCE_DIR_PROTOBUF=/deps/protobuf \
    -DFETCHCONTENT_SOURCE_DIR_ABSL=/deps/abseil-cpp \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON"

# Enable ONNX's built-in sanitizer support so the C++ extensions are
# instrumented alongside the Python atheris layer.
if [[ "$SANITIZER" == "address" || "$SANITIZER" == "undefined" ]]; then
  CMAKE_ARGS="$CMAKE_ARGS -DONNX_USE_ASAN=ON"
fi

# Strip -fsanitize=fuzzer-no-link before building the Python extension.
# That flag adds sancov coverage symbols (__sancov_lowest_stack etc.) that are
# only provided by libFuzzer at run time, causing an undefined-symbol error when
# plain Python tries to import the .so.  ASan instrumentation is kept so the
# extension still detects memory bugs during fuzzing.
# Use Python for reliable whitespace-token stripping (bash ${//} can silently
# fail to match when the env var contains trailing punctuation or odd spacing).
export CFLAGS=$(python3 -c "
import os, sys
flags = os.environ.get('CFLAGS', '')
print(' '.join(f for f in flags.split() if f != '-fsanitize=fuzzer-no-link'))
")
export CXXFLAGS=$(python3 -c "
import os, sys
flags = os.environ.get('CXXFLAGS', '')
print(' '.join(f for f in flags.split() if f != '-fsanitize=fuzzer-no-link'))
")
pip3 install --no-build-isolation .

python3 $SRC/onnx/onnx/fuzz/make_seed_corpus.py \
    $OUT/fuzz_version_converter_seed_corpus.zip \
    $OUT/fuzz_parser_seed_corpus.zip \
    $OUT/fuzz_checker_seed_corpus.zip \
    $OUT/fuzz_shape_inference_seed_corpus.zip

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC/onnx/onnx/fuzz -maxdepth 1 -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done
