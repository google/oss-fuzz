#!/bin/bash -eux
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
rake all

# Build the test driver so that run_tests.sh has something to run. Allowed to
# fail; run_tests.sh is what gates on the test results.
rake test:build || true

# build fuzzers
FUZZ_TARGET=$SRC/mruby/oss-fuzz/mruby_fuzzer.c
name=$(basename $FUZZ_TARGET .c)
$CC -c $CFLAGS -Iinclude -Ibuild/host/include \
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

# Build the proto fuzzer, for libFuzzer with ASan or UBSan only.
#
# libprotobuf-mutator drives this target through LLVMFuzzerCustomMutator, which
# is a libFuzzer-only interface. Under AFL++ or honggfuzz that hook is never
# called, so the target degrades to byte mutation of a serialized protobuf,
# where almost every input fails to parse and never reaches mruby at all. It is
# therefore not worth building for the other engines, and building it there
# drags libprotobuf-mutator and the whole protobuf/absl static link surface into
# those links, which is where the AFL build breaks with undefined references to
# google::protobuf symbols taking std::__1::basic_string_view: the mutator and
# its bundled protobuf disagree on whether absl::string_view is std::string_view.
#
# MemorySanitizer is excluded because neither protobuf nor libprotobuf-mutator
# is MSan-instrumented, which would produce false reports.
if [[ $FUZZING_ENGINE == libfuzzer && $CFLAGS != *sanitize=memory* ]]; then
    PROTO_FUZZ_TARGET=$SRC/mruby/oss-fuzz/mruby_proto_fuzzer.cpp
    PROTO_CONVERTER=$SRC/mruby/oss-fuzz/proto_to_ruby.cpp
    rm -rf $SRC/mruby/genfiles
    mkdir $SRC/mruby/genfiles
    # Everything that touches protobuf headers must agree with the C++ standard
    # the bundled protobuf and abseil were compiled with, which
    # libprotobuf-mutator hard-codes to 14 in
    # cmake/external/protobuf.cmake (-DCMAKE_CXX_STANDARD=14). Abseil selects
    # between its own absl::string_view and std::string_view based on that
    # standard, so a C++17 consumer of a C++14 build looks for
    # google::protobuf symbols taking std::__1::basic_string_view and fails to
    # link. The Dockerfile pins libprotobuf-mutator itself to the same
    # standard; PROTO_STD keeps these translation units in step.
    PROTO_STD="-std=c++14"
    $SRC/LPM/external.protobuf/bin/protoc --proto_path=$SRC/mruby/oss-fuzz ruby.proto --cpp_out=$SRC/mruby/genfiles
    $CXX -c $CXXFLAGS $PROTO_STD $SRC/mruby/genfiles/ruby.pb.cc -DNDEBUG -o $SRC/mruby/genfiles/ruby.pb.o -I $SRC/LPM/external.protobuf/include
    $CXX -I $SRC/mruby/include -I $SRC/mruby/build/host/include -I $SRC/LPM/external.protobuf/include $CXXFLAGS $PROTO_STD $PROTO_FUZZ_TARGET $SRC/mruby/genfiles/ruby.pb.o $PROTO_CONVERTER \
      -I $SRC/mruby/genfiles \
      -I $SRC/libprotobuf-mutator \
      -lz -lm \
      $SRC/LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
      $SRC/LPM/src/libprotobuf-mutator.a \
      -Wl,--start-group $SRC/LPM/external.protobuf/lib/lib*.a -Wl,--end-group \
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
