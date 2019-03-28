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

# Build boost statically, linking it against libc++
cd $SRC/boost
./bootstrap.sh --with-toolset=clang
./b2 clean
./b2 toolset=clang cxxflags="-stdlib=libc++" linkflags="-stdlib=libc++" headers
./b2 toolset=clang cxxflags="-stdlib=libc++" linkflags="-stdlib=libc++" \
     link=static variant=release runtime-link=static \
     system regex filesystem unit_test_framework program_options \
     install -j $(($(nproc)/2))


# Compile proto C++ bindings
cd $SRC
LPM/external.protobuf/bin/protoc \
    --proto_path=$SRC/solidity/test/tools/ossfuzz yulProto.proto \
    --cpp_out=$SRC/solidity/test/tools/ossfuzz

# Build solidity
cd $SRC/solidity
BASE_CXXFLAGS="$CXXFLAGS"
CXXFLAGS="$BASE_CXXFLAGS -I/usr/local/include/c++/v1 -L/usr/local/lib"
mkdir -p build
cd build
rm -rf *

# Build solidity
cmake -DUSE_Z3=OFF -DUSE_CVC4=OFF -DOSSFUZZ=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DBoost_FOUND=1 \
  -DBoost_USE_STATIC_LIBS=1 \
  -DBoost_USE_STATIC_RUNTIME=1 \
  -DBoost_INCLUDE_DIR=/usr/local/include/ \
  -DBoost_FILESYSTEM_LIBRARY=/usr/local/lib/libboost_filesystem.a \
  -DBoost_FILESYSTEM_LIBRARIES=/usr/local/lib/libboost_filesystem.a \
  -DBoost_PROGRAM_OPTIONS_LIBRARY=/usr/local/lib/libboost_program_options.a \
  -DBoost_PROGRAM_OPTIONS_LIBRARIES=/usr/local/lib/libboost_program_options.a \
  -DBoost_REGEX_LIBRARY=/usr/local/lib/libboost_regex.a \
  -DBoost_REGEX_LIBRARIES=/usr/local/lib/libboost_regex.a \
  -DBoost_SYSTEM_LIBRARY=/usr/local/lib/libboost_system.a \
  -DBoost_SYSTEM_LIBRARIES=/usr/local/lib/libboost_system.a \
  -DBoost_UNIT_TEST_FRAMEWORK_LIBRARY=/usr/local/lib/libboost_unit_test_framework.a \
  -DBoost_UNIT_TEST_FRAMEWORK_LIBRARIES=/usr/local/lib/libboost_unit_test_framework.a \
  $SRC/solidity
make ossfuzz ossfuzz_proto -j $(nproc)

# Copy fuzzer binary, seed corpus, fuzzer options, and dictionary
cp test/tools/ossfuzz/*_ossfuzz $OUT/
rm -f $OUT/*.zip
for dir in $SRC/solidity-fuzzing-corpus/*;
do
	name=$(basename $dir)
	zip -ujq $OUT/$name.zip $dir/* &>/dev/null
done
cp $SRC/solidity/test/tools/ossfuzz/config/*.options $OUT/
cp $SRC/solidity/test/tools/ossfuzz/config/*.dict $OUT/
