#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# setup
build=${WORK}/build

# cleanup
rm -rf ${build}
mkdir -p ${build}

# build library
meson -Dbuild_asm=false -Dbuild_tools=false -Dbuild_tests=false   \
      -Db_lundef=false -Ddefault_library=static -Dbuildtype=debugoptimized \
      ${build}
ninja -j $(nproc) -C ${build}

# build fuzzer
$CC $CFLAGS -Iinclude \
    -o ${build}/dav1d_fuzzer.o -c tests/libfuzzer/dav1d_fuzzer.c
$CXX $CXXFLAGS -lFuzzingEngine \
    ${build}/dav1d_fuzzer.o -o $OUT/dav1d_fuzzer \
    ${build}/src/libdav1d.a

# get see corpus
rm -rf ${WORK}/tmp
mkdir -p ${WORK}/tmp/testdata
unzip -q $SRC/dav1d_fuzzer_seed_corpus.zip -d ${WORK}/tmp/testdata
cp $SRC/dec_fuzzer_seed_corpus.zip $OUT/dav1d_fuzzer_seed_corpus.zip
(cd ${WORK}/tmp && zip -q -m -r -0 $OUT/dav1d_fuzzer_seed_corpus.zip testdata)
