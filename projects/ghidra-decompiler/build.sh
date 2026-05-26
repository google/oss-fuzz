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
# OSS-Fuzz build script for the GayHydra decompiler harnesses.
# See https://codeberg.org/CryptoJones/GayHydra/src/branch/master/docs/security/OSS_FUZZ.md.

CPP_DIR="$SRC/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
FUZZ_DIR="$CPP_DIR/fuzz"

cd "$CPP_DIR"

# Build decompiler object files with the OSS-Fuzz sanitizers.
# The decompiler's existing Makefile produces objects in-place; we
# don't link the main binary, only the .o files our harnesses need.
make OPT_CXXFLAGS="$CXXFLAGS" \
     OPT_LDFLAGS="" \
     bare_libdecomp.a 2>/dev/null || \
make OPT_CXXFLAGS="$CXXFLAGS" \
     OPT_LDFLAGS="" \
     xml.o marshal.o address.o space.o

cd "$FUZZ_DIR"

for harness in fuzz_xml fuzz_marshal; do
    $CXX $CXXFLAGS -std=c++11 -I"$CPP_DIR" -c "$harness.cc" -o "$harness.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE "$harness.o" \
        "$CPP_DIR"/xml.o "$CPP_DIR"/marshal.o \
        "$CPP_DIR"/address.o "$CPP_DIR"/space.o \
        -o "$OUT/$harness"

    # Copy seed corpus if it exists.
    if [ -d "$FUZZ_DIR/seeds/$harness" ]; then
        ( cd "$FUZZ_DIR/seeds/$harness" && \
          zip -r "$OUT/${harness}_seed_corpus.zip" . )
    fi
done
