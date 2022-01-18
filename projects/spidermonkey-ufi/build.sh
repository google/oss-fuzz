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

# Ensure rust nightly is used
source $HOME/.cargo/env
rustup default nightly

# Install dependencies.
export MOZBUILD_STATE_PATH=/root/.mozbuild
export SHELL=/bin/bash
../../mach --no-interactive bootstrap --application-choice browser

autoconf2.13

# Skip patches for now
rm ../../tools/fuzzing/libfuzzer/patches/*.patch
touch ../../tools/fuzzing/libfuzzer/patches/dummy.patch

# Update internal libFuzzer.
(cd ../../tools/fuzzing/libfuzzer && ./clone_libfuzzer.sh HEAD)

mkdir -p build_OPT.OBJ
cd build_OPT.OBJ

if [ "$SANITIZER" = coverage ]; then
  SAN_OPT="--enable-coverage"
else
  SAN_OPT="--enable-$SANITIZER-sanitizer"
fi

../configure \
    --enable-debug \
    --enable-optimize="-O2 -gline-tables-only" \
    --disable-jemalloc \
    --enable-tests \
    --enable-fuzzing \
    $SAN_OPT

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
