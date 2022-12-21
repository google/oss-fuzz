#!/bin/bash -eu
# Copyright 2022 Google LLC
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
pushd test/
patch < CMakeLists.txt.patch
popd

mkdir build && cd build

cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_UNIT_TESTS=ON -DBUILD_SHARED_LIBS=OFF -DWITH_SNAPPY=ON \
-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
-DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CFLAGS" \
-DCMAKE_CPP_FLAGS="$CFLAGS" -DCMAKE_EXE_LINKER_FLAGS="$CFLAGS -Wl,-rpath,'\$ORIGIN/lib'" \
-DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
../

make -j$(nproc)

pushd test/
cp Fuzz_json $OUT/Fuzz_json
cp Fuzz_http $OUT/Fuzz_http
popd

pushd $SRC/oss-fuzz-bloat/brpc/
cp Fuzz_json_seed_corpus.zip $OUT/Fuzz_json_seed_corpus.zip
cp Fuzz_http_seed_corpus.zip $OUT/Fuzz_http_seed_corpus.zip
popd

pushd /lib/x86_64-linux-gnu/
mkdir $OUT/lib/
cp libgflags* $OUT/lib/.
cp libprotobuf* $OUT/lib/.
cp libleveldb* $OUT/lib/.
cp libprotoc* $OUT/lib/.
cp libsnappy* $OUT/lib/.
popd
