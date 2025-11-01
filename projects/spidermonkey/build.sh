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

# Write mozconfig file.
echo '
ac_add_options --enable-application=js
mk_add_options MOZ_OBJDIR=@TOPSRCDIR@/obj-shell

ac_add_options --enable-debug
ac_add_options --enable-optimize="-O2 -gline-tables-only"

ac_add_options --disable-jemalloc
ac_add_options --disable-tests
ac_add_options --enable-address-sanitizer

CFLAGS="-fsanitize=address"
CXXFLAGS="-fsanitize=address"
LDFLAGS="-fsanitize=address"
' > ./mozconfig
export MOZCONFIG=./mozconfig

# Install dependencies.
./mach --no-interactive bootstrap --application-choice js

./mach build "-j$(nproc)"

cp obj-shell/dist/bin/js $OUT

# Copy libraries.
mkdir -p $OUT/lib
cp -L /usr/lib/x86_64-linux-gnu/libc++.so.1 $OUT/lib
cp -L /usr/lib/x86_64-linux-gnu/libc++abi.so.1 $OUT/lib

# Make sure libs are resolved properly
patchelf --set-rpath '$ORIGIN/lib'  $OUT/js
