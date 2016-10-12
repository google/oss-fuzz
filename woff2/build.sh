#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# Checkout woff2 repository with submodules.
mkdir -p /work/woff2
cd /work/woff2
git clone https://github.com/google/woff2 --recursive

# Build the library. Actually there is no 'library' target, so we use .o files.
# '-no-canonical-prefixes' flag makes clang crazy. Need to avoid it.
cd woff2
cat brotli/shared.mk | sed -e "s/-no-canonical-prefixes//" \
> brotli/shared.mk.temp
mv brotli/shared.mk.temp brotli/shared.mk

cat Makefile | sed -e "s/-no-canonical-prefixes//" \
> Makefile.temp
mv Makefile.temp Makefile

# woff2 uses LFLAGS instead of LDFLAGS.
export LFLAGS=$LDFLAGS
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" clean all

# To avoid multiple main() definitions.
rm src/woff2_compress.o src/woff2_decompress.o

# Build the fuzzer.
fuzzer=convert_woff2ttf_fuzzer
$CXX $CXXFLAGS -std=c++11 -Isrc \
    /src/oss-fuzz/woff2/$fuzzer.cc -o /out/$fuzzer \
    /work/libfuzzer/*.o src/*.o brotli/dec/*.o brotli/enc/*.o $LDFLAGS
