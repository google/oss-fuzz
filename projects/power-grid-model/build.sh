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

# The fuzz harnesses, seed corpora, and dictionary are maintained upstream under
# tests/fuzzer/ in the power-grid-model repository and are present in the clone
# at $SRC/power-grid-model. Nothing fuzzing-related is vendored here.
PGM_SRC="$SRC/power-grid-model"
FUZZ_DIR="$PGM_SRC/tests/fuzzer"

# ---------------------------------------------------------------------------
# 1. Build the Power Grid Model C API (shared library) with OSS-Fuzz flags.
# ---------------------------------------------------------------------------
cd "$PGM_SRC"

# Force the source-installed Boost 1.84 in /usr/local. base-builder ships a
# broken/older Boost at /usr/include; PGM sets CMP0167 OLD (FindBoost module
# mode) but not CMP0144, so BOOST_ROOT is ignored and BOOST_INCLUDEDIR is only
# a soft hint that loses to /usr/include. Pre-seeding the FindBoost cache
# variable Boost_INCLUDE_DIR makes the module skip searching and use our copy.
#
# -fexperimental-library un-hides std::jthread / <stop_token> in base-builder's
# libc++ (PGM uses std::jthread in job_dispatch.hpp) and links libc++experimental.
#
# No CMAKE_BUILD_TYPE on purpose: Release would append -O3 -DNDEBUG after
# $CFLAGS/$CXXFLAGS, overriding OSS-Fuzz's optimization level and compiling out
# every assert() in the library — exactly the checks fuzzing should trip.
cmake -S . -B build -G Ninja \
    -DPGM_ENABLE_DEV_BUILD=OFF \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
    -DBoost_NO_SYSTEM_PATHS=ON \
    -DBoost_INCLUDE_DIR=/usr/local/include \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS -fexperimental-library"

cmake --build build --target power_grid_model_c -j"$(nproc)"

# ---------------------------------------------------------------------------
# 2. Compile and link each harness against the public C API.
#
# The harnesses are built here rather than through the project's own
# PGM_ENABLE_FUZZER CMake option because OSS-Fuzz supplies its own fuzzing
# engine via $LIB_FUZZING_ENGINE; the CMake path exists for local AFL++ and
# libFuzzer builds and selects an engine itself.
# ---------------------------------------------------------------------------
PGM_C_INC="$PGM_SRC/power_grid_model_c/power_grid_model_c/include"
PGM_C_LIBDIR="$PGM_SRC/build/bin"

# harness source basename -> seed corpus directory
declare -A HARNESS_CORPUS=(
    [fuzz_deserialize_json]=corpus_json
    [fuzz_parse_to_buffer]=corpus_json
    [fuzz_model_create]=corpus_json
    [fuzz_power_flow]=corpus_json
    [fuzz_state_estimation]=corpus_json
    [fuzz_short_circuit]=corpus_json
    [fuzz_model_batch_update]=corpus_update
)

for harness in "${!HARNESS_CORPUS[@]}"; do
    # -I$FUZZ_DIR picks up the shared fuzz_*.h headers and base_grid.h.
    $CC $CFLAGS -I"$PGM_C_INC" -I"$FUZZ_DIR" \
        -c "$FUZZ_DIR/${harness}.c" -o "$WORK/${harness}.o"

    # Linked as C++ because the C API library is C++ internally.
    $CXX $CXXFLAGS "$WORK/${harness}.o" -o "$OUT/${harness}" \
        $LIB_FUZZING_ENGINE \
        -L"$PGM_C_LIBDIR" -lpower_grid_model_c \
        -Wl,-rpath,'$ORIGIN/lib'
done

# The shared library travels with the targets; $ORIGIN/lib above is what lets
# them find it inside the OSS-Fuzz runner.
mkdir -p "$OUT/lib"
cp -a "$PGM_C_LIBDIR"/libpower_grid_model_c.so* "$OUT/lib/"

# ---------------------------------------------------------------------------
# 3. Seed corpora and dictionary (shipped from the upstream tree).
#
# Every harness parses the same JSON envelope, so they share one dictionary.
# All but the batch target take any document and share corpus_json; the batch
# target takes update documents for its fixed grid.
# ---------------------------------------------------------------------------
for harness in "${!HARNESS_CORPUS[@]}"; do
    corpus="${HARNESS_CORPUS[$harness]}"
    # zip appends to an existing archive. $OUT is normally fresh, but a local
    # rebuild into a reused output directory would otherwise silently merge the
    # previous corpus into the new one.
    rm -f "$OUT/${harness}_seed_corpus.zip"
    zip -j -q "$OUT/${harness}_seed_corpus.zip" "$FUZZ_DIR/${corpus}"/*
    cp "$FUZZ_DIR/pgm.dict" "$OUT/${harness}.dict"
done
