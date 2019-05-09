#!/bin/bash -eu
#
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

MBEDTLS_BUILD=$WORK/mbedtls
S2OPC_BUILD=$WORK/s2opc
SAMPLES=$SRC/S2OPC-fuzzing-data

# Build the dependencies
tar xzf $SRC/mbedtls.tgz -C $WORK
mkdir -p $MBEDTLS_BUILD
cd $MBEDTLS_BUILD
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON $WORK/mbedtls-2.*
make -j$(nproc)
make -j$(nproc) install

tar xzf $SRC/check.tgz -C $WORK
cd $WORK/check-0.*
./configure --prefix=/usr/local --with-tcltk=no
make -j$(nproc)
make -j$(nproc) install

# Build S2OPC and the fuzzers
mkdir -p $S2OPC_BUILD
cd $S2OPC_BUILD
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_EXE_LINKER_FLAGS="$CXXFLAGS" \
      -DCMAKE_C_LINK_EXECUTABLE="$CXX <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS>  -o <TARGET> <LINK_LIBRARIES>" \
      -DWITH_OSS_FUZZ=ON \
      $SRC/S2OPC
cmake --build . --target fuzzers

# Copy them and build the corpora
cp bin/* $OUT

cd $SAMPLES
for dir in $(ls -d */); do
    zip -j $OUT/${dir%/}_fuzzer_seed_corpus.zip ${dir}*
done
