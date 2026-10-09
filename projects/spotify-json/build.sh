#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Build spotify-json
mkdir build
pushd build
cmake -DSPOTIFY_JSON_BUILD_TESTS=OFF ../
make -j$(nproc) spotify-json

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ../fuzzers//fuzz_decode.cpp \
    -I../include -I../vendor/double-conversion \
    ./libspotify-json.a ./vendor/double-conversion/libdouble-conversion.a  -lpthread -o $OUT/fuzz_decode
popd

# Build unit testing and benchmark which is incompatible with major build with fuzzing sanitizer
mkdir build-tests
pushd build-tests
unset CXXFLAGS
cmake -DSPOTIFY_JSON_BUILD_TESTS=ON -DCMAKE_CXX_FLAGS='-stdlib=libstdc++' ../
make -j$(nproc) spotify_json_test json_benchmark
popd
