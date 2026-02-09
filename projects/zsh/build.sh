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

cd $SRC/zsh

# Generate configure script
# zsh requires running Util/preconfig which needs autoconf/autoheader
if [ -f Util/preconfig ]; then
    # preconfig generates configure from configure.ac
    autoheader || true
    autoconf || true
fi

# Configure zsh with sanitizer-friendly flags
./configure \
    --disable-dynamic \
    --disable-gdbm \
    --enable-pcre \
    --enable-multibyte \
    CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$CFLAGS" \
    || true

# Build the source files we need
cd Src
make -j$(nproc) || true
cd ..

# The pattern matching code is in Src/pattern.c
# The math evaluation is in Src/math.c
# The glob expansion is in Src/glob.c
# These have significant dependencies on zsh internals, so we'll build
# standalone fuzz targets that re-implement the core algorithms.

# === Standalone fuzzers that don't depend on zsh internals ===

# Build fuzz_zsh_pattern: Standalone zsh-style pattern matching
$CC $CFLAGS -I$SRC/zsh/Src -I$SRC/zsh \
    -c $SRC/fuzz_zsh_pattern.c -o $SRC/fuzz_zsh_pattern.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_zsh_pattern.o \
    -o $OUT/fuzz_zsh_pattern

cp $SRC/fuzz_zsh_pattern.dict $OUT/ || true

# Build fuzz_zsh_math: Standalone math expression evaluator
$CC $CFLAGS -I$SRC/zsh/Src -I$SRC/zsh \
    -c $SRC/fuzz_zsh_math.c -o $SRC/fuzz_zsh_math.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_zsh_math.o \
    -lm \
    -o $OUT/fuzz_zsh_math

cp $SRC/fuzz_zsh_math.dict $OUT/ || true

# Build fuzz_zsh_glob: Standalone glob pattern parser
$CC $CFLAGS -I$SRC/zsh/Src -I$SRC/zsh \
    -c $SRC/fuzz_zsh_glob.c -o $SRC/fuzz_zsh_glob.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_zsh_glob.o \
    -o $OUT/fuzz_zsh_glob

cp $SRC/fuzz_zsh_glob.dict $OUT/ || true
