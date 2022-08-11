#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

# Ensure rust nightly is used
source $HOME/.cargo/env
rustup default nightly

# Install dependencies.
export MOZBUILD_STATE_PATH=/root/.mozbuild
export SHELL=/bin/bash
cd ../../
./mach --no-interactive bootstrap --application-choice browser
cd js/src/

autoconf2.13

mkdir build_DBG.OBJ
cd build_DBG.OBJ

../configure \
    --enable-debug \
    --enable-optimize="-O2 -gline-tables-only" \
    --disable-jemalloc \
    --disable-tests \
    --enable-address-sanitizer

make "-j$(nproc)"

cp dist/bin/js $OUT

# Copy libraries.
mkdir -p $OUT/lib
cp -L /usr/lib/x86_64-linux-gnu/libc++.so.1 $OUT/lib
cp -L /usr/lib/x86_64-linux-gnu/libc++abi.so.1 $OUT/lib

# Make sure libs are resolved properly
patchelf --set-rpath '$ORIGIN/lib'  $OUT/js
