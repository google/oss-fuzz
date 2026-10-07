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
cd build
cmake ../ -DDISABLE_SHARED=ON -LH
make clean

# Ensure we do static linking
sed -i 's/libmariadb SHARED/libmariadb STATIC/g' ../libmariadb/libmariadb/CMakeLists.txt
make
rm CMakeCache.txt

# Build fuzzers
INCLUDE_DIRS="-I/src/server/wsrep-lib/include -I/src/server/wsrep-lib/wsrep-API/v26 -I/src/server/build/include -I/src/server/include/providers -I/src/server/include -I/src/server/sql -I/src/server/regex -I/src/server/unittest/mytap"
$CC $CFLAGS $INCLUDE_DIRS -c $SRC/fuzz_json.c -o ./fuzz_json.o

# Link with CXX to support centipede
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_json.o -o $OUT/fuzz_json \
	-Wl,--start-group ./unittest/mytap/libmytap.a ./strings/libstrings.a \
	./dbug/libdbug.a ./mysys/libmysys.a -Wl,--end-group -lz -ldl -lpthread
