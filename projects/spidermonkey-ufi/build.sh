#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Case-sensitive names of internal Firefox fuzzing targets. Edit to add more.
FUZZ_TARGETS=(
  StructuredCloneReader
  Wasm
)

# Install dependencies. Note that bootstrap installs cargo, which must be added
# to PATH via source. In a successive run (for a different sanitizer), the
# cargo installation carries over, but bootstrap fails if cargo is not in PATH.
export SHELL=/bin/bash
[[ -f "$HOME/.cargo/env" ]] && source $HOME/.cargo/env
../../mach bootstrap --no-interactive --application-choice browser
source $HOME/.cargo/env

autoconf2.13

# Update internal libFuzzer.
(cd ../../tools/fuzzing/libfuzzer && ./clone_libfuzzer.sh HEAD)

mkdir -p build_OPT.OBJ
cd build_OPT.OBJ

../configure \
    --enable-optimize \
    --disable-shared-js \
    --disable-jemalloc \
    --enable-tests \
    --enable-fuzzing \
    --enable-$SANITIZER-sanitizer

make "-j$(nproc)"

cp dist/bin/fuzz-tests $OUT

# Build a wrapper binary for each target to set environment variables.
for FUZZ_TARGET in ${FUZZ_TARGETS[@]}
do
  $CC $CFLAGS -O0 \
    -DFUZZ_TARGET=$FUZZ_TARGET \
    $SRC/target.c -o $OUT/$FUZZ_TARGET
done

# Copy libraries.
mkdir -p $OUT/lib
cp -L /usr/lib/x86_64-linux-gnu/libc++.so.1 $OUT/lib
cp -L /usr/lib/x86_64-linux-gnu/libc++abi.so.1 $OUT/lib

