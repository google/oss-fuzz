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

cd "$SRC/onnx"

# Build ONNX's own protobuf from source so it is compiled with -fPIC,
# which is required to link into the Python extension .so.
# Point FetchContent at pre-downloaded sources so cmake needs no network access.
export CMAKE_ARGS="-DONNX_BUILD_CUSTOM_PROTOBUF=ON \
    -DFETCHCONTENT_SOURCE_DIR_PROTOBUF=/deps/protobuf \
    -DFETCHCONTENT_SOURCE_DIR_ABSL=/deps/abseil-cpp \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON"

# Keep the OSS-Fuzz compiler flags so ONNX's native parser, checker, shape
# inference, and protobuf code are instrumented as well as the Python harness.
pip3 install --no-build-isolation .

# An extension built with -fsanitize=fuzzer-no-link needs Atheris' combined
# sanitizer/libFuzzer runtime whenever a normal Python process imports it. The
# runtime is copied to $OUT by OSS-Fuzz's Python build setup before build.sh is
# called. Coverage builds do not create or need this library.
python_runtime=()
if [[ "$SANITIZER" == "address" || "$SANITIZER" == "undefined" ]]; then
  python_runtime=(env \
    LD_PRELOAD="$OUT/sanitizer_with_fuzzer.so${LD_PRELOAD:+:$LD_PRELOAD}" \
    ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=0")

  onnx_extension=$("${python_runtime[@]}" python3 -c \
    'import onnx.onnx_cpp2py_export as extension; print(extension.__file__)')
  if ! nm -D "$onnx_extension" | grep -q '__sanitizer_cov_'; then
    echo "ONNX native extension has no sanitizer-coverage instrumentation" >&2
    exit 1
  fi
fi

"${python_runtime[@]}" python3 "$SRC/onnx/onnx/fuzz/make_seed_corpus.py" \
    "$OUT/fuzz_version_converter_seed_corpus.zip" \
    "$OUT/fuzz_parser_seed_corpus.zip" \
    "$OUT/fuzz_checker_seed_corpus.zip" \
    "$OUT/fuzz_shape_inference_seed_corpus.zip"

# Coverage builds: compile_python_fuzzer prepends a stub containing real Python
# statements (import atexit, import coverage ...) before each fuzzer file.
# Any 'from __future__' import then appears after those statements and causes
# SyntaxError. Strip them from the in-container copies only.
if [[ "$SANITIZER" == "coverage" ]]; then
  find "$SRC/onnx/onnx/fuzz" -maxdepth 1 -name 'fuzz_*.py' -print0 | \
    while IFS= read -r -d '' f; do
      sed -i '/^from __future__ import/d' "$f"
    done
fi

# Build fuzzers in $OUT.
# --collect-all numpy bundles all numpy C extensions including numpy._core.*
# which PyInstaller 6.x does not pick up automatically with numpy 2.x.
find "$SRC/onnx/onnx/fuzz" -maxdepth 1 -name 'fuzz_*.py' -print0 | \
  while IFS= read -r -d '' fuzzer; do
    "${python_runtime[@]}" compile_python_fuzzer "$fuzzer" --collect-all numpy
  done
