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

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link against 32-bit libraries

# Package seed corpus
zip $OUT/seed_corpus.zip *.*

# Build project
mkdir build && cd build
cmake .. -DCMAKE_C_FLAGS="${CFLAGS}" \
         -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
         -DCMAKE_LINKER="${LD}" \
         -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}" \
         -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}" \
         -DBUILD_SHARED_LIBS=OFF \
         -DWITH_FUZZERS=ON
make clean
make -j $(nproc)

# Copy seed corpus for each fuzzer target
for f in $(find . -type f -name 'fuzzer_*'); do
    cp -v $f $OUT
    (cd $OUT; ln -s seed_corpus.zip $(basename $f)_seed_corpus.zip)
done
