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

cd unicorn
mkdir build
cd build

# CC CXX should be auto retrieved by cmake.
cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=off -DUNICORN_FUZZ=1
make -j4

libs="libunicorn.a \
libx86_64-softmmu.a \
libaarch64-softmmu.a \
libarm-softmmu.a \
libm68k-softmmu.a \
libmips64el-softmmu.a \
libmips64-softmmu.a \
libmipsel-softmmu.a \
libmips-softmmu.a \
libppc64-softmmu.a \
libppc-softmmu.a \
libriscv32-softmmu.a \
libriscv64-softmmu.a \
libsparc64-softmmu.a \
libsparc-softmmu.a \
libs390x-softmmu.a \
libunicorn-common.a"


ls ../tests/fuzz/fuzz_*.c | cut -d_ -f2-4 | cut -d. -f1 | while read target
do
    FUZZO=CMakeFiles/fuzz_$target.dir/tests/fuzz/fuzz_$target.c.o 
    $CXX $CXXFLAGS $FUZZO $libs -lpthread -lrt -lm -o $OUT/fuzz_$target $LIB_FUZZING_ENGINE
    cp ../tests/fuzz/fuzz_emu.options $OUT/fuzz_$target.options
done
