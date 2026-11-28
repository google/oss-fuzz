#!/bin/bash -eu
# Copyright 2023 Google LLC.
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

export LDFLAGS="${CFLAGS}"
SRC_DIR="$SRC/hdf5"

mkdir -p "$SRC_DIR/build-dir"
cd "$SRC_DIR/build-dir"
cmake -G "Unix Makefiles" \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DCMAKE_BUILD_TYPE:STRING=Release \
    -DBUILD_SHARED_LIBS:BOOL=OFF \
    -DBUILD_TESTING:BOOL=OFF \
    -DHDF5_BUILD_EXAMPLES:BOOL=OFF \
    -DHDF5_BUILD_TOOLS:BOOL=OFF \
    -DHDF5_ENABLE_SANITIZERS:BOOL=ON \
    -DHDF5_ENABLE_Z_LIB_SUPPORT:BOOL=ON \
    -DHDF5_ENABLE_FUZZERS:BOOL=ON \
    ..
cmake --build . --target oss-fuzz-fuzzers --config Release -j"$(nproc)"

# Stage every built fuzzer binary into $OUT (CMake leaves them in the build
# tree). Auto-detect by name: any executable ending in _fuzzer.
find "$SRC_DIR/build-dir" -type f -executable -name '*_fuzzer' -exec cp -v {} "$OUT/" \;

# Seed corpora and any per-fuzzer options shipped with the harnesses.
zip -j "$OUT/h5_extended_fuzzer_seed_corpus.zip" "$SRC_DIR/test/testfiles/"*.h5
cp "$SRC_DIR/test/fuzzing/"*.options "$OUT/" 2>/dev/null || true
