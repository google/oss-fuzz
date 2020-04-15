#!/bin/bash -eu
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
cd fluent-bit/build
cmake -DFLB_RECORD_ACCESSOR=Off -DFLB_STREAM_PROCESSOR=Off -DFLB_LUAJIT=OFF ..
make || true

# Copy over the fuzzers
cp ../tests/internal/fuzzers/* .

# Now compile the fuzzers
$CC $CFLAGS -c flb_json_fuzzer.c -o flb_json_fuzzer.o
$CXX flb_json_fuzzer.o -o $OUT/flb_json_fuzzer $CXXFLAGS $LIB_FUZZING_ENGINE  library/libfluent-bit.a  library/libmk_core.a library/libjsmn.a library/libmsgpackc.a library/libmpack-static.a
