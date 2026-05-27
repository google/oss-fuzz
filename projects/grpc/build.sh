#!/bin/bash -eu
#
# Copyright 2024 Google LLC
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
###############################################################################

cd $SRC/grpc

# Synchronize grpc dependencies
python3 tools/buildgen/generate_projects.py 2>/dev/null || true

# Build the compression fuzzers using Bazel with OSS-Fuzz config
bazel build \
    --config=oss-fuzz \
    --action_env=FUZZING_CFLAGS="$CFLAGS" \
    --action_env=FUZZING_CXXFLAGS="$CXXFLAGS" \
    --action_env=LIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
    //test/core/compression:message_compress_fuzzer \
    //test/core/compression:message_decompress_fuzzer

cp bazel-bin/test/core/compression/message_compress_fuzzer $OUT/
cp bazel-bin/test/core/compression/message_decompress_fuzzer $OUT/
