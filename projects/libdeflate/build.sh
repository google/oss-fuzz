#!/bin/bash -eu
# Copyright 2026 Google Inc.
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

TARGETS=(deflate_compress deflate_decompress gzip_decompress zlib_decompress)

cd $SRC/libdeflate

cmake -B build && cmake --build build

cd scripts/libFuzzer/

for target in "${TARGETS[@]}"; do
    $CC $CFLAGS -g -O1 -Wall -Werror -DLIBDEFLATE_ENABLE_ASSERTIONS=1 -I ../../ \
        $LIB_FUZZING_ENGINE \
        ../../lib/*{,/}*.c "$target/fuzz.c" \
        -o "$OUT/$target"
    cd "$target/corpus"
    zip "$target"_seed_corpus.zip *
    mv "$target"_seed_corpus.zip $OUT
    cd ../..
done
