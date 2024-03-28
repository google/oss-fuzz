#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

./bootstrap.sh --with-libraries=json

echo "using clang : ossfuzz : $CXX : <compileflags>\"$CXXFLAGS\" <linkflags>\"$CXXFLAGS\" <linkflags>\"${LIB_FUZZING_ENGINE}\" ;" >user-config.jam

./b2 --user-config=user-config.jam --toolset=clang-ossfuzz --prefix=$WORK/stage --with-json link=static install

for i in libs/json/fuzzing/*.cpp; do
   fuzzer=$(basename $i .cpp)
   $CXX $CXXFLAGS -pthread libs/json/fuzzing/$fuzzer.cpp -I $WORK/stage/include/ $WORK/stage/lib/*.a $LIB_FUZZING_ENGINE -o $OUT/$fuzzer
done

# ProtobufMutator does not currently support MSan
if [[ $CFLAGS = *sanitize=memory* ]]; then
    exit 0
fi

# For fuzz-introspector, cxclude all functions in the fluent-bit/lib/ directory
export FUZZ_INTROSPECTOR_CONFIG=$SRC/fuzz_introspector_exclusion.config
cat > $FUZZ_INTROSPECTOR_CONFIG <<EOF
FILES_TO_AVOID
LPM
genfiles
EOF

# TODO: remove this when upstream merge the new fuzzer
cp $SRC/fuzz_proto_parser.cc libs/json/fuzzing/fuzz_proto_parser.cc
cp $SRC/json_proto_converter.cc libs/json/fuzzing/json_proto_converter.cc
cp $SRC/json_proto_converter.h libs/json/fuzzing/json_proto_converter.h

# Add dictionary.
cp $SRC/json_fuzzer.dict $OUT/json_fuzzer.dict

# Compile json proto.
rm -rf genfiles && mkdir genfiles && LPM/external.protobuf/bin/protoc json.proto --cpp_out=genfiles --proto_path=$SRC

# Compile LPM fuzzer.
$CXX $CXXFLAGS -I genfiles -I libs/json/fuzzing -I libprotobuf-mutator/ -I LPM/external.protobuf/include -I $WORK/stage/include/ $LIB_FUZZING_ENGINE \
    libs/json/fuzzing/fuzz_proto_parser.cc genfiles/json.pb.cc libs/json/fuzzing/json_proto_converter.cc \
    LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    LPM/src/libprotobuf-mutator.a \
    -Wl,--start-group LPM/external.protobuf/lib/lib*.a -Wl,--end-group \
    -o  $OUT/fuzz_proto_parser \
    $WORK/stage/lib/*.a
