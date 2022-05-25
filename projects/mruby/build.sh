#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Instrument mruby
(
cd $SRC/mruby
export LD=$CC
export LDFLAGS="$CFLAGS"
rake -m

# build fuzzers
FUZZ_TARGET=$SRC/mruby/oss-fuzz/mruby_fuzzer.c
name=$(basename $FUZZ_TARGET .c)
$CC -c $CFLAGS -Iinclude \
     ${FUZZ_TARGET} -o $OUT/${name}.o
$CXX $CXXFLAGS $OUT/${name}.o $LIB_FUZZING_ENGINE -lm \
    $SRC/mruby/build/host/lib/libmruby.a -o $OUT/${name}
rm -f $OUT/${name}.o
)

# Construct options files
cat > $SRC/mruby/oss-fuzz/config/mruby_fuzzer.options <<EOF
[libfuzzer]
dict = mruby.dict
only_ascii = 1
EOF
cp $SRC/mruby/oss-fuzz/config/mruby_fuzzer.options $SRC/mruby/oss-fuzz/config/mruby_proto_fuzzer.options

# Build proto fuzzer: ASan and UBSan
if [[ $CFLAGS != *sanitize=memory* ]]; then
    PROTO_FUZZ_TARGET=$SRC/mruby/oss-fuzz/mruby_proto_fuzzer.cpp
    PROTO_CONVERTER=$SRC/mruby/oss-fuzz/proto_to_ruby.cpp
    rm -rf $SRC/mruby/genfiles
    mkdir $SRC/mruby/genfiles
    $SRC/LPM/external.protobuf/bin/protoc --proto_path=$SRC/mruby/oss-fuzz ruby.proto --cpp_out=$SRC/mruby/genfiles
    $CXX -c $CXXFLAGS $SRC/mruby/genfiles/ruby.pb.cc -DNDEBUG -o $SRC/mruby/genfiles/ruby.pb.o -I $SRC/LPM/external.protobuf/include
    $CXX -I $SRC/mruby/include -I $SRC/LPM/external.protobuf/include $CXXFLAGS $PROTO_FUZZ_TARGET $SRC/mruby/genfiles/ruby.pb.o $PROTO_CONVERTER \
      -I $SRC/mruby/genfiles \
      -I $SRC/libprotobuf-mutator \
      -I $SRC/mruby/include -lz -lm \
      $SRC/LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
      $SRC/LPM/src/libprotobuf-mutator.a \
      $SRC/LPM/external.protobuf/lib/libprotobuf.a \
      $SRC/mruby/build/host/lib/libmruby.a \
      $LIB_FUZZING_ENGINE \
      -o $OUT/mruby_proto_fuzzer

    # Copy config
    cp $SRC/mruby/oss-fuzz/config/mruby_proto_fuzzer.options $OUT
fi

# dict and config
cp $SRC/mruby/oss-fuzz/config/mruby.dict $OUT
cp $SRC/mruby/oss-fuzz/config/mruby_fuzzer.options $OUT

# seeds
zip -rq $OUT/mruby_fuzzer_seed_corpus $SRC/mruby_seeds
