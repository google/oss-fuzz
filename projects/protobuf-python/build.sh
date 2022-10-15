#!/bin/bash -eu
# Copyright 2022 Google LLC
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

BAZEL_FLAGS="-c dbg"
if [[ $CFLAGS = *sanitize=address* ]]
then
    BAZEL_FLAGS="$BAZEL_FLAGS --config=asan"
fi

# Build protoc with default options.
unset CFLAGS CXXFLAGS
cd $SRC/protobuf
bazel build $BAZEL_FLAGS //:protoc @upb//python/dist:binary_wheel
PROTOC=$(realpath bazel-bin/protoc)

# Install the protobuf python runtime.
mkdir $SRC/wheels
find -L bazel-out -name 'protobuf*.whl' -exec mv '{}' $SRC/wheels ';'
pip3 install -vvv --no-index --find-links $SRC/wheels protobuf

# Compile test protos with protoc.
cd $SRC/
$PROTOC --python_out=. --proto_path=. test-full.proto

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done
