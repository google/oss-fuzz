#!/bin/bash -eu
# Copyright 2020 Google Inc.
# Copyright 2020 Luca Boccassi <bluca@debian.org>
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

# Avoid: clang++: error: invalid argument '-fsanitize=vptr' not allowed with '-fno-rtti'
CFLAGS="$CFLAGS     -fno-sanitize=vptr"
CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr"

# Pick C++17 due to use of std::filesystem
CXXFLAGS="$CXXFLAGS -std=c++17"

cd $SRC/leveldb
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DLEVELDB_BUILD_TESTS=0 \
    -DLEVELDB_BUILD_BENCHMARKS=0 -DCMAKE_CXX_STANDARD=17 .. && cmake --build .

for fuzzer in fuzz_db; do
    # Compile
    $CXX $CXXFLAGS -c ../${fuzzer}.cc -o ${fuzzer}.o \
        -DLEVELDB_PLATFORM_POSIX=1 -Wall \
        -I$SRC/leveldb/build/include -I$SRC/leveldb/ -I$SRC/leveldb/include

    # Link
    $CXX $LIB_FUZZING_ENGINE $CXXFLAGS ${fuzzer}.o -o $OUT/${fuzzer} $SRC/leveldb/build/libleveldb.a
done

# Copy options to out
cp $SRC/*options $OUT/
