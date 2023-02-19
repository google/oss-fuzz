#!/bin/bash -eu
# Copyright 2023 Google LLC
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
mkdir build 

pushd build/

cmake \
    -DCMAKE_BUILD_TYPE=Debug -DBUILD_OSSFUZZ=ON \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_EXE_LINKER_FLAGS="$CFLAGS" \
    -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" ../.

make -j$(nproc)

cp fuzz/fuzz_url $OUT/fuzz_url
cp fuzz/fuzz_table $OUT/fuzz_table
cp fuzz/fuzz_server $OUT/fuzz_server
popd

zip -j ${OUT}/fuzz_url_seed_corpus.zip fuzz/input/fuzz_url.raw
zip -j ${OUT}/fuzz_table_seed_corpus.zip fuzz/input/fuzz_table.raw
zip -j ${OUT}/fuzz_server_seed_corpus.zip fuzz/input/fuzz_server.raw
