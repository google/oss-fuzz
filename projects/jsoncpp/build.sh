#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

mkdir -p build
cd build
cmake -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles" ..
make

# Compile fuzzer.
$CXX $CXXFLAGS -I../include $LIB_FUZZING_ENGINE \
    ../src/test_lib_json/fuzz.cpp -o $OUT/jsoncpp_fuzzer \
    lib/libjsoncpp.a

# Add dictionary.
cp $SRC/jsoncpp/src/test_lib_json/fuzz.dict $OUT/jsoncpp_fuzzer.dict

if [[ $CFLAGS != *sanitize=memory* ]]; then
# Compile json proto.
rm -rf genfiles && mkdir genfiles && ../LPM/external.protobuf/bin/protoc json.proto --cpp_out=genfiles --proto_path=$SRC

# Compile LPM fuzzer.
$CXX $CXXFLAGS -DNDEBUG -I genfiles -I .. -I ../libprotobuf-mutator/ -I ../LPM/external.protobuf/include -I ../include $LIB_FUZZING_ENGINE \
    $SRC/jsoncpp_fuzz_proto.cc genfiles/json.pb.cc $SRC/json_proto_converter.cc \
    ../LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    ../LPM/src/libprotobuf-mutator.a \
    ../LPM/external.protobuf/lib/libprotobuf.a \
    -o  $OUT/jsoncpp_proto_fuzzer \
    lib/libjsoncpp.a
fi
