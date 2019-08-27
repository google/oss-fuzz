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

# Based on the function from oss-fuzz/projects/golang/build.sh script.
function compile_fuzzer {
  path=$1
  function=$2
  fuzzer=$3

   # Instrument all Go files relevant to this fuzzer
  go-fuzz-build -libfuzzer -func $function -o $fuzzer.a $path 

   # Instrumented, compiled Go ($fuzzer.a) + fuzzing engine = fuzzer binary
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -lpthread -o $OUT/$fuzzer
}

compile_fuzzer ./pkg/compiler Fuzz compiler_fuzzer
compile_fuzzer ./prog/test FuzzDeserialize prog_deserialize_fuzzer
compile_fuzzer ./prog/test FuzzParseLog prog_parselog_fuzzer
compile_fuzzer ./pkg/report Fuzz report_fuzzer

# This target is way too spammy and OOMs very quickly.
# compile_fuzzer ./tools/syz-trace2syz/proggen Fuzz trace2syz_fuzzer
