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

#builds project
cd keystone
mkdir build
cd build
cmake ..
make

# build fuzz target
cd ../suite/fuzz
ls fuzz_*.c | cut -d_ -f2-4 | cut -d. -f1 | while read target
do
    $CC $CFLAGS -I../../include -c fuzz_$target.c -o fuzz_$target.o

    $CXX $CXXFLAGS fuzz_$target.o -o $OUT/fuzz_$target ../../build/llvm/lib/libkeystone.a $LIB_FUZZING_ENGINE

    #TODO corpuses
    cp fuzz_asm.options $OUT/fuzz_$target.options
done
