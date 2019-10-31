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

# Compile proto C++ bindings
protoc \
    --proto_path=$SRC/solidity/test/tools/ossfuzz yulProto.proto \
    --cpp_out=$SRC/solidity/test/tools/ossfuzz
protoc \
    --proto_path=$SRC/solidity/test/tools/ossfuzz abiV2Proto.proto \
    --cpp_out=$SRC/solidity/test/tools/ossfuzz

# Build solidity
cd $SRC/solidity
CXXFLAGS="${CXXFLAGS} -I/usr/local/include/c++/v1"
mkdir -p build
cd build
rm -rf *

# Build solidity
cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/ossfuzz.cmake \
      -DCMAKE_BUILD_TYPE=Release \
      $SRC/solidity
make ossfuzz ossfuzz_proto ossfuzz_abiv2 -j $(nproc)

# Copy fuzzer binary, seed corpus, fuzzer options, and dictionary
cp test/tools/ossfuzz/*_ossfuzz $OUT/
rm -f $OUT/*.zip
for dir in $SRC/solidity-fuzzing-corpus/*;
do
	name=$(basename $dir)
	zip -rjq $OUT/$name $dir
done
cp $SRC/solidity/test/tools/ossfuzz/config/*.options $OUT/
cp $SRC/solidity/test/tools/ossfuzz/config/*.dict $OUT/
