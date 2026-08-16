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

# Build the Python extension with a clean compiler environment.
# The OSS-Fuzz CFLAGS contain -fsanitize=fuzzer-no-link which references
# __sancov_lowest_stack — a symbol only provided by libFuzzer at runtime —
# causing ImportError when plain Python imports the .so. Atheris handles
# instrumentation at the Python level, so the extension does not need these
# flags. This follows the same pattern used by numpy, pyyaml, and others.
unset CFLAGS CXXFLAGS LIB_FUZZING_ENGINE
pip3 install --no-build-isolation .

python3 $SRC/onnx/onnx/fuzz/make_seed_corpus.py \
    $OUT/fuzz_version_converter_seed_corpus.zip \
    $OUT/fuzz_parser_seed_corpus.zip \
    $OUT/fuzz_checker_seed_corpus.zip \
    $OUT/fuzz_shape_inference_seed_corpus.zip

# Coverage builds: compile_python_fuzzer prepends a stub containing real Python
# statements (import atexit, import coverage ...) before each fuzzer file.
# Any 'from __future__' import then appears after those statements and causes
# SyntaxError. Strip them from the in-container copies only.
if [[ "$SANITIZER" == "coverage" ]]; then
  for f in $(find $SRC/onnx/onnx/fuzz -maxdepth 1 -name 'fuzz_*.py'); do
    sed -i '/^from __future__ import/d' "$f"
  done
fi

# Build fuzzers in $OUT.
# --collect-all numpy bundles all numpy C extensions including numpy._core.*
# which PyInstaller 6.x does not pick up automatically with numpy 2.x.
for fuzzer in $(find $SRC/onnx/onnx/fuzz -maxdepth 1 -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer --collect-all numpy
done
