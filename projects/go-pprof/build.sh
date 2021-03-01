#!/bin/bash -eu
# Copyright 2021 Google LLC
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

compile_go_fuzzer ./fuzz Fuzz fuzz

mkdir fuzzlpm
$SRC/LPM/external.protobuf/bin/protoc --cpp_out=fuzzlpm/ proto/profile.proto

$CXX $CXXFLAGS -c -I fuzzlpm/ -I $SRC/LPM/external.protobuf/include fuzzlpm/proto/profile.pb.cc
$CXX $CXXFLAGS -c -I. -I ../libprotobuf-mutator/ -I $SRC/LPM/external.protobuf/include $SRC/go-lpm.cc

(
cd $SRC/go114-fuzz-build
sed -i -e 's/LLVMFuzzerTestOneInput/LPMFuzzerTestOneInput/' main.go
go build
)

$SRC/go114-fuzz-build/go114-fuzz-build -func Fuzz -o fuzz_lpm.a ./fuzzproto
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE profile.pb.o go-lpm.o fuzz_lpm.a  $SRC/LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a $SRC/LPM/src/libprotobuf-mutator.a $SRC/LPM/external.protobuf/lib/libprotobuf.a -o $OUT/fuzz_lpm

# generate corpus
zip -r $OUT/fuzz_seed_corpus.zip ./fuzz/corpus
