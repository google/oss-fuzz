#!/bin/bash
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

set -o nounset
set -o pipefail
set -o errexit
set -x

# Based on the function from oss-fuzz/projects/golang/build.sh script.
function compile_fuzzer {
  local pkg=$1
  local function=$2
  local fuzzer="${pkg}_${function}"

   # Instrument all Go files relevant to this fuzzer
  go-fuzz-build -libfuzzer -func "${function}" -o "${fuzzer}.a" "k8s.io/kubernetes/test/fuzz/${pkg}"

   # Instrumented, compiled Go ($fuzzer.a) + fuzzing engine = fuzzer binary
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE "${fuzzer}.a" -lpthread -o "${OUT}/${fuzzer}"
}

compile_fuzzer "yaml" "FuzzDurationStrict"
compile_fuzzer "yaml" "FuzzMicroTimeStrict"
compile_fuzzer "yaml" "FuzzSigYaml"
compile_fuzzer "yaml" "FuzzTimeStrict"
compile_fuzzer "yaml" "FuzzYamlV2"
compile_fuzzer "json" "FuzzStrictDecode"
compile_fuzzer "json" "FuzzNonStrictDecode"
