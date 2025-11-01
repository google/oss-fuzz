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

# Move seed corpus and dictionary.
mv $SRC/{*.zip,*.dict} $OUT

mkdir build && cd build
cmake ../ -DBUILD_SHARED_LIBS=OFF
make
$CC $CFLAGS -c ../test/fuzzers/fuzz-mdhtml.c -I../src
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-mdhtml.o -o $OUT/fuzz-mdhtml \
    ./src/libmd4c-html.a ./src/libmd4c.a
