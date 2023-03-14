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

# required by Go 1.20
export CXX="${CXX} -lresolv"

# Compile kOps fuzzers
(
cd kops
./tests/fuzz/build.sh
)

# Compile Kubernetes fuzzers
cd $SRC/kubernetes

function compile_fuzzer {
  local pkg=$1
  local function=$2
  local fuzzer="${pkg}_${function}"

  compile_go_fuzzer "k8s.io/kubernetes/test/fuzz/${pkg}" $function $fuzzer
}

# Build fuzzers from cncf-fuzzing:
$SRC/cncf-fuzzing/projects/kubernetes/build.sh


compile_fuzzer "yaml" "FuzzDurationStrict"
compile_fuzzer "yaml" "FuzzMicroTimeStrict"
compile_fuzzer "yaml" "FuzzSigYaml"
compile_fuzzer "yaml" "FuzzTimeStrict"
compile_fuzzer "yaml" "FuzzYamlV2"
compile_fuzzer "json" "FuzzStrictDecode"
compile_fuzzer "json" "FuzzNonStrictDecode"
