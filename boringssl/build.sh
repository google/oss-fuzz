#!/bin/bash -eux
#
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
. /env

mkdir -p /work/boringssl
cd /work/boringssl

CFLAGS="$CFLAGS -DBORINGSSL_UNSAFE_FUZZER_MODE"
CXXFLAGS="$CXXFLAGS -DBORINGSSL_UNSAFE_FUZZER_MODE"

cmake -GNinja -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
    /src/boringssl/
ninja

fuzzerFiles=$(find /src/boringssl/fuzz/ -name "*.cc")

find . -name "*.a"

for F in $fuzzerFiles; do
  fuzzerName=$(basename $F .cc)
  echo "Building fuzzer $fuzzerName"
  $CXX $CXXFLAGS $LDFLAGS -std=c++11 -o /out/openssl_${fuzzerName} /work/libfuzzer/*.o $F \
  -I /src/boringssl/include ./ssl/libssl.a  ./crypto/libcrypto.a
done

