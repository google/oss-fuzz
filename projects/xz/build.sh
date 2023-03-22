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
  --disable-encoders \
  --disable-xz \
  --disable-xzdec \
  --disable-lzmadec \
  --disable-lzmainfo
make clean
make -j$(nproc) && make -C tests/ossfuzz && \
    cp tests/ossfuzz/config/fuzz.options $OUT/ && \
    cp tests/ossfuzz/config/fuzz.dict $OUT && \
    find $SRC/xz/tests/files -name "*.xz" \
    -exec zip -ujq $OUT/fuzz_seed_corpus.zip "{}" \;
