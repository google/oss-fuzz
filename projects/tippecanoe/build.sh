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

# Build tippecanoe
make -j$(nproc)

# Rebuild main()
sed 's/int main(int argc/int main2(int argc/g' -i ./jsontool.cpp
$CXX $CXXFLAGS -MMD  -I/usr/local/include -I. -g -O3 -DNDEBUG -std=c++11 \
-c -o jsontool.o jsontool.cpp

# Build fuzzer
$CXX $CXXFLAGS -MMD  -I/usr/local/include -I. -g -O3 -DNDEBUG \
  -std=c++11 -c $SRC/json_fuzzer.cc -o json_fuzzer.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -g -O3 -std=c++11 \
  json_fuzzer.o -o $OUT/json_fuzzer jsontool.o jsonpull/jsonpull.o \
  csv.o text.o geojson-loop.o  -lm -lz -lsqlite3 -lpthread
