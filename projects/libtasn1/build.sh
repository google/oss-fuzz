#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

./bootstrap
# switch off leak detection for ./configure run to detect iconv() correctly
ASAN_OPTIONS=detect_leaks=0 ./configure --enable-static --disable-shared --disable-doc --disable-gcc-warnings --enable-fuzzing
make clean
make -j$(nproc) -C lib
make -j$(nproc) -C src
make -j$(nproc) -C tests check

cd fuzz
make oss-fuzz
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'

for dir in *_fuzzer.in; do
  fuzzer=$(basename $dir .in)
  zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "${dir}/"
done
