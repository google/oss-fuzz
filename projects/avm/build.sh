#!/bin/bash -eu
# Copyright 2026 Google LLC
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

build_dir="$WORK/build"
rm -rf "$build_dir"
mkdir -p "$build_dir"

extra_flags="-DDO_RANGE_CHECK_CLAMP=1 -DAVM_MAX_ALLOCABLE_MEMORY=1073741824"

cmake -S "$SRC/avm" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DAVM_EXTRA_C_FLAGS="$extra_flags" \
  -DAVM_EXTRA_CXX_FLAGS="$extra_flags" \
  -DCONFIG_PIC=1 \
  -DCONFIG_AV2_ENCODER=0 \
  -DCONFIG_SIZE_LIMIT=1 \
  -DDECODE_HEIGHT_LIMIT=12288 \
  -DDECODE_WIDTH_LIMIT=12288 \
  -DENABLE_APPS=0 \
  -DENABLE_DOCS=0 \
  -DENABLE_EXAMPLES=0 \
  -DENABLE_TESTS=0 \
  -DENABLE_TOOLS=0

cmake --build "$build_dir" --parallel "$(nproc)"

"$CXX" $CXXFLAGS -std=c++11 -DDECODER=av2 \
  -I"$SRC/avm" -I"$build_dir" \
  "$SRC/avm/examples/av2_dec_fuzzer.cc" \
  -o "$OUT/av2_dec_fuzzer" \
  "$LIB_FUZZING_ENGINE" "$build_dir/libavm.a"
