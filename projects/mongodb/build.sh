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

mkdir cmake-build && cd cmake-build
cmake -DENABLE_MONGOC=OFF -DENABLE_BSON_AUTO=ON -DENABLE_STATIC=ON ../ 
make

$CC $CFLAGS -I./src \
    -I./src/libbson/src -I./src/libbson/src/bson -I./src/common \
    -I../src/libbson/src -I../src/libbson/src/bson -I../src/common \
    -c ../src/libbson/fuzz/fuzz_test_libbson.c -o fuzz_test_libbson.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_test_libbson.o \
    ./src/libbson/libbson-static-1.0.a -o $OUT/fuzz-libbson
