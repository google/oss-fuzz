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

mkdir fuzzlpm
$SRC/LPM/external.protobuf/bin/protoc --cpp_out=fuzzlpm/ -I$SRC/ $SRC/cel-go-lpm.proto

$CXX $CXXFLAGS -DNDEBUG -c -I fuzzlpm/ -I $SRC/LPM/external.protobuf/include fuzzlpm/cel-go-lpm.pb.cc
$CXX $CXXFLAGS -DNDEBUG -c -I. -I ../libprotobuf-mutator/ -I $SRC/LPM/external.protobuf/include $SRC/go-lpm.cc

(
cd $SRC/go114-fuzz-build
sed -i -e 's/LLVMFuzzerTestOneInput/LPMFuzzerTestOneInput/' main.go
go build
)

$SRC/LPM/external.protobuf/bin/protoc --go_out=fuzzlpm/ -I$SRC/ $SRC/cel-go-lpm.proto
cp fuzzlpm/github.com/google/cel-go/cel/*.pb.go cel/

$SRC/go114-fuzz-build/go114-fuzz-build -func FuzzEval -o fuzz_lpm.a github.com/google/cel-go/cel
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE cel-go-lpm.pb.o go-lpm.o fuzz_lpm.a  $SRC/LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a $SRC/LPM/src/libprotobuf-mutator.a $SRC/LPM/external.protobuf/lib/libprotobuf.a -o $OUT/fuzz_lpm

compile_go_fuzzer github.com/google/cel-go/cel FuzzCompile fuzz_compile
