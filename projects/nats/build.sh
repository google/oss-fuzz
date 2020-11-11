#/bin/bash -eu
# Copyright 2020 Google Inc.
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
function compile_fuzzer {
  path=$1
  function=$2
  fuzzer=$3

  go-fuzz -func $function -o $fuzzer.a $path

  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -o $OUT/$fuzzer
}

compile_fuzzer github.com/nats-io/nats-server/conf Fuzz fuzz_conf
compile_fuzzer github.com/nats-io/nats-server/server FuzzClient fuzz_client
