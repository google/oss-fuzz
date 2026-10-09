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

# Build yyjson as a static library
mkdir -p build && cd build
cmake .. -DCMAKE_C_COMPILER="$CC" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_SHARED_LIBS=OFF \
         -DYYJSON_BUILD_TESTS=OFF \
         -DYYJSON_BUILD_FUZZER=OFF \
         -DYYJSON_INSTALL=OFF
make -j$(nproc)
cd ..

build_fuzzer() {
  local source_file="$1"
  local output_name="$2"

  $CC $CFLAGS -I src -c "$source_file" -o "$WORK/$output_name.o"
  $CXX $CXXFLAGS "$WORK/$output_name.o" -o "$OUT/$output_name" \
    $LIB_FUZZING_ENGINE build/libyyjson.a
}

build_fuzzer fuzz/fuzzer.c yyjson_fuzzer
build_fuzzer fuzz/patch_fuzzer.c yyjson_patch_fuzzer
build_fuzzer fuzz/merge_patch_fuzzer.c yyjson_merge_patch_fuzzer

# Copy the dictionary
cp fuzz/fuzzer.dict $OUT/yyjson_fuzzer.dict
cp fuzz/fuzzer.dict $OUT/yyjson_patch_fuzzer.dict
cp fuzz/fuzzer.dict $OUT/yyjson_merge_patch_fuzzer.dict

# Build seed corpus from upstream test data
mkdir -p /tmp/yyjson_corpus
find test/data/json -name "*.json" -exec cp {} /tmp/yyjson_corpus/ \;
zip -jq $OUT/yyjson_fuzzer_seed_corpus.zip /tmp/yyjson_corpus/*

# Generate seed corpora for the patch fuzz targets
python3 "$SRC/generate_patch_corpora.py" --out-dir "$OUT"
