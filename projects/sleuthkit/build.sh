#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

export CFLAGS="$CFLAGS -Wno-error=non-c-typedef-for-linkage"
export CXXFLAGS="$CXXFLAGS -Wno-error=non-c-typedef-for-linkage"

# Work around convolution around building static library versus static binaries
# Also see: https://github.com/sleuthkit/sleuthkit/issues/3020
sed -i 's/-all-static//g' configure.ac

# Work around hardcoded -Werror flags
# Also see: https://github.com/sleuthkit/sleuthkit/issues/3012
sed -i 's/-Werror//g' Makefile.am

# Don't fail if some of the seed downloads fail.
./ossfuzz/buildcorpus.sh || true

./bootstrap
./configure --enable-static --enable-shared=no --disable-java --without-afflib --without-libcrypto --without-libewf --without-libvhdi --without-libvmdk
make -j$(nproc)

# Copy the fuzzer binaries to the output directory.
cp *_fuzzer ${OUT}
