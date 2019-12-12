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

# build target function
function compile_fuzzer {
  path=$1
  function=$2
  fuzzer=$3

   # Instrument all Go files relevant to this fuzzer
  go-fuzz-build -libfuzzer -func $function -o $fuzzer.a $path

   # Instrumented, compiled Go ($fuzzer.a) + fuzzing engine = fuzzer binary
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -lpthread -o $OUT/$fuzzer
}

compile_fuzzer /root/go/src/github.com/google/gonids/ FuzzParseRule fuzz_parserule

unzip emerging.rules.zip
cd rules
i=0
mkdir corpus
# quit output for commands
set +x
cat *.rules | while read l; do echo $l > corpus/$i.rule; i=$((i+1)); done
set -x
zip -r $OUT/fuzz_parserule_seed_corpus.zip corpus
