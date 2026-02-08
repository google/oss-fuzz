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

cd $SRC/neovim

# Strip sanitizer/fuzzer flags for building neovim itself.
# Neovim's build uses luajit to generate code (via libnlua0.so),
# and sanitizer flags like -fsanitize=fuzzer-no-link introduce
# __sancov_lowest_stack which luajit can't resolve at load time.
# We only need sanitizers when compiling our fuzz targets.
NVIM_CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only"

# Build neovim's bundled dependencies (static libraries)
cmake -S cmake.deps -B .deps -G Ninja \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_C_COMPILER=$CC \
    -D CMAKE_C_FLAGS="$NVIM_CFLAGS"
cmake --build .deps

# Build neovim itself (produces libnvim.a with all nvim code including vterm)
# We use the same clean NVIM_CFLAGS here — no sanitizer, no coverage flags.
# Coverage instrumentation in CMAKE_C_FLAGS would contaminate libnlua0.so
# (the build-time code generator loaded by luajit), causing unresolved
# __sanitizer_cov_trace_* symbols. The fuzz targets themselves are compiled
# with full $CFLAGS (including coverage), which provides sufficient coverage.
cmake -S . -B build -G Ninja \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_C_COMPILER=$CC \
    -D CMAKE_C_FLAGS="$NVIM_CFLAGS"
cmake --build build --target libnvim

# Collect include paths that neovim's build uses
NVIM_INCLUDES="\
    -I $SRC/neovim/build/src/nvim/auto \
    -I $SRC/neovim/build/include \
    -I $SRC/neovim/build/cmake.config \
    -I $SRC/neovim/src \
    -I $SRC/neovim/.deps/usr/include \
    -I $SRC/neovim/.deps/usr/include/luajit-2.1"

################################################################################
# Target 1: fuzz_nvim_vterm — Terminal escape sequence parser
#
# The fuzzer defines xmalloc/xfree stubs that override libnvim.a's memory.c.
# We use --allow-multiple-definition because libnvim.a's memory.c.o and main.c.o
# get pulled in transitively (other .o files reference symbols they define).
# Our fuzzer .o comes first, so the linker picks our simple stubs.
################################################################################
$CC $CFLAGS $NVIM_INCLUDES \
    -c $SRC/fuzz_nvim_vterm.c -o $WORK/fuzz_nvim_vterm.o

# Collect all static dependency libraries from .deps
NVIM_DEPS=""
for lib in $SRC/neovim/.deps/usr/lib/*.a; do
    NVIM_DEPS="$NVIM_DEPS $lib"
done

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $WORK/fuzz_nvim_vterm.o \
    -Wl,--allow-multiple-definition \
    $SRC/neovim/build/lib/libnvim.a \
    $NVIM_DEPS \
    -lutil -lpthread -ldl -lm \
    -o $OUT/fuzz_nvim_vterm

################################################################################
# Target 2: fuzz_nvim_base64 — Base64 encode/decode
################################################################################
$CC $CFLAGS $NVIM_INCLUDES \
    -c $SRC/fuzz_nvim_base64.c -o $WORK/fuzz_nvim_base64.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $WORK/fuzz_nvim_base64.o \
    -Wl,--allow-multiple-definition \
    $SRC/neovim/build/lib/libnvim.a \
    $NVIM_DEPS \
    -lutil -lpthread -ldl -lm \
    -o $OUT/fuzz_nvim_base64

################################################################################
# Target 3: fuzz_nvim_mpack — MessagePack tokenizer (completely standalone)
#
# mpack under src/mpack/ has ZERO nvim dependencies — it's pure C with
# no xmalloc, no nvim headers. We compile mpack_core.c directly.
################################################################################
$CC $CFLAGS -I $SRC/neovim/src \
    -c $SRC/fuzz_nvim_mpack.c -o $WORK/fuzz_nvim_mpack.o

$CC $CFLAGS -I $SRC/neovim/src \
    -c $SRC/neovim/src/mpack/mpack_core.c -o $WORK/mpack_core.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $WORK/fuzz_nvim_mpack.o \
    $WORK/mpack_core.o \
    -o $OUT/fuzz_nvim_mpack

# Copy dictionaries (named to match fuzz targets for auto-association)
cp $SRC/fuzz_nvim_vterm.dict $OUT/
cp $SRC/fuzz_nvim_base64.dict $OUT/
cp $SRC/fuzz_nvim_mpack.dict $OUT/
