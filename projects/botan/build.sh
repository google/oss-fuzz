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

cd $SRC/botan

# This assumes $CC is set to either 'clang' or 'gcc'
./configure.py --cc=$CC --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" \
               --unsafe-fuzzer-mode --disable-shared --disable-modules=locking_allocator
make -j$(nproc) libbotan-2.a

jigs=$(find $SRC/botan/src/extra_tests/fuzzers/jigs -name "*.cpp")

for fuzzer_src in $jigs; do
  fuzzer=$(basename $fuzzer_src .cpp)
  $CXX $CXXFLAGS -DUSE_LLVM_FUZZER -std=c++11 -I$SRC/botan/build/include \
       -o $OUT/$fuzzer $fuzzer_src -L$SRC/botan -lbotan-2 -lFuzzingEngine

  if [ -d "$SRC/crypto-corpus/${fuzzer}" ]; then
    zip -j $OUT/${fuzzer}_seed_corpus.zip $SRC/crypto-corpus/${fuzzer}/*
  fi
done

