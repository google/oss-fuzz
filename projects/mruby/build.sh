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
export LD=clang
export LDFLAGS="$CFLAGS"
./minirake clean && ./minirake -j$(nproc) all

# build fuzzers
FUZZ_TARGET=$SRC/mruby/oss-fuzz/mruby_fuzzer.c
name=$(basename $FUZZ_TARGET .c)
$CC -c $CFLAGS -Iinclude \
     ${FUZZ_TARGET} -o $OUT/${name}.o
$CXX $CXXFLAGS $OUT/${name}.o $LIB_FUZZING_ENGINE -lm \
    $SRC/mruby/build/host/lib/libmruby.a -o $OUT/${name}
rm -f $OUT/${name}.o
)

# Build proto fuzzer: ASan and UBSan
if [[ $CFLAGS != *sanitize=memory* ]]; then
    PROTO_FUZZ_TARGET=$SRC/mruby/oss-fuzz/mruby_proto_fuzzer.cpp
    PROTO_CONVERTER=$SRC/mruby/oss-fuzz/proto_to_ruby.cpp
    rm -rf genfiles
    mkdir genfiles
    LPM/external.protobuf/bin/protoc --proto_path=mruby/oss-fuzz ruby.proto --cpp_out=genfiles
    $CXX $CXXFLAGS $PROTO_FUZZ_TARGET genfiles/ruby.pb.cc $PROTO_CONVERTER \
      -I genfiles -I mruby/oss-fuzz  -I libprotobuf-mutator/ -I .  \
      -I LPM/external.protobuf/include \
      -I mruby/include -lz -lm \
      LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
      LPM/src/libprotobuf-mutator.a \
      LPM/external.protobuf/lib/libprotobuf.a \
      mruby/build/host/lib/libmruby.a \
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
