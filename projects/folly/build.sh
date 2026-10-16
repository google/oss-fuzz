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
#
################################################################################
#
# Build script for the Folly OSS-Fuzz integration.
#
# Strategy:
#  1. Build Folly as a static library using CMake + Ninja, honouring the
#     sanitizer flags injected by the OSS-Fuzz harness ($CC/$CXX/$CFLAGS/
#     $CXXFLAGS).
#  2. Compile each fuzz target from folly/fuzz/ directly with $CXX so that
#     $LIB_FUZZING_ENGINE (the fuzzing-engine flag or library provided by the
#     OSS-Fuzz harness) is wired in correctly.
#  3. Install the resulting binaries into $OUT.

readonly FOLLY_SRC="$SRC/folly"
readonly BUILD_DIR="$FOLLY_SRC/_build"
readonly FUZZ_SRC="$FOLLY_SRC/folly/fuzz"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# ---------------------------------------------------------------------------
# Step 1 – build the Folly library
# ---------------------------------------------------------------------------
cmake "$FOLLY_SRC" \
  -G Ninja \
  -DCMAKE_C_COMPILER="${CC}" \
  -DCMAKE_CXX_COMPILER="${CXX}" \
  -DCMAKE_C_FLAGS="${CFLAGS}" \
  -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
  -DCMAKE_CXX_STANDARD=20 \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DFOLLY_USE_JEMALLOC=OFF \
  -DBUILD_TESTS=OFF \
  -DBUILD_BENCHMARKS=OFF \
  -DBUILD_FUZZ_TARGETS=OFF  # fuzz targets compiled separately below

cmake --build . -j"$(nproc)" --target folly

# ---------------------------------------------------------------------------
# Step 2 – compile and link each fuzz target
# ---------------------------------------------------------------------------

# The generated folly-config.h lives in the build directory; headers in source.
INCLUDES="-I${FOLLY_SRC} -I${BUILD_DIR}"

# System libraries that folly depends on (order matters for GNU ld static libs).
SYS_LIBS="\
  -lboost_filesystem -lboost_system -lboost_thread -lboost_regex \
  -lglog -lgflags -lfmt -ldouble-conversion \
  -lssl -lcrypto -levent \
  -lsnappy -llz4 -lzstd -lz -lbz2 \
  -lunwind -lelf \
  -lpthread -ldl -latomic"

FOLLY_LIB="${BUILD_DIR}/libfolly.a"

for fuzzer_src in "${FUZZ_SRC}"/*_fuzzer.cc; do
  fuzzer_name="$(basename "${fuzzer_src%.cc}")"
  echo "Building ${fuzzer_name} ..."
  "$CXX" $CXXFLAGS -std=c++20 \
    $INCLUDES \
    "${fuzzer_src}" \
    $LIB_FUZZING_ENGINE \
    -Wl,--start-group "${FOLLY_LIB}" -Wl,--end-group \
    $SYS_LIBS \
    -o "${OUT}/${fuzzer_name}"

  # Package the seed corpus if a corpus directory exists for this target.
  corpus_dir="${FUZZ_SRC}/corpus/${fuzzer_name}"
  if [[ -d "${corpus_dir}" ]]; then
    zip -j "${OUT}/${fuzzer_name}_seed_corpus.zip" "${corpus_dir}"/*
  fi
done
