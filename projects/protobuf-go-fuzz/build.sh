#!/bin/bash -eu
# Copyright 2025 Google LLC
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

# build project
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \
#     $LIB_FUZZING_ENGINE /path/to/library.a

#!/bin/bash -eu

# Build the Unmarshal harness
compile_native_go_fuzzer \
  github.com/protocolbuffers/protobuf-go/reflect/protoreflect/fuzz \
  FuzzAnyUnmarshal \
  fuzz_anyunmarshal \
  fuzz

# Build the Merge harness
compile_native_go_fuzzer \
  github.com/protocolbuffers/protobuf-go/reflect/protoreflect/fuzz \
  FuzzMergeMessage \
  fuzz_merge_message \
  fuzz

# Build the JSON/Bin diff harness
compile_native_go_fuzzer \
  github.com/protocolbuffers/protobuf-go/reflect/protoreflect/fuzz \
  FuzzJSONBinaryDiff \
  fuzz_json_binary_diff \
  fuzz
