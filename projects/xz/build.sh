#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

./autogen.sh --no-po4a --no-doxygen
./configure \
  --enable-static \
  --disable-debug \
  --disable-shared \
  --disable-xz \
  --disable-xzdec \
  --disable-lzmadec \
  --disable-lzmainfo \
  --disable-ifunc

make clean
make -j$(nproc)
for fuzz_target in $(sed -nr 's/(fuzz.*):.*/\1/p' $SRC/xz/tests/ossfuzz/Makefile); do
  make $fuzz_target -C tests/ossfuzz
done

cp $SRC/xz/tests/ossfuzz/config/*.options $OUT/
cp $SRC/xz/tests/ossfuzz/config/*.dict $OUT/

find $SRC/xz/tests/files -name "*.lzma" \
-exec zip -ujq $OUT/fuzz_decode_alone_seed_corpus.zip "{}" \;
find $SRC/xz/tests/files ! -name "*.lzma_raw" \
-exec zip -ujq $OUT/fuzz_decode_auto_seed_corpus.zip "{}" \;
find $SRC/xz/tests/files -name "*.lz" \
-exec zip -ujq $OUT/fuzz_decode_lzip_seed_corpus.zip "{}" \;
find $SRC/xz/tests/files -name "*.lzma_raw" \
-exec zip -ujq $OUT/fuzz_decode_raw_seed_corpus.zip "{}" \;
find $SRC/xz/tests/files -name "*.lzma2*" \
-exec zip -ujq $OUT/fuzz_decode_raw_lzma2_seed_corpus.zip "{}" \;
find $SRC/xz/tests/files -name "*.xz" \
-exec zip -ujq $OUT/fuzz_decode_stream_seed_corpus.zip "{}" \;
find $SRC/xz/tests/files -name "*.xz" \
-exec zip -ujq $OUT/fuzz_decode_stream_crc_seed_corpus.zip "{}" \;