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

. contrib/oss-fuzz/build.sh

# Seed corpora and dictionaries for new fuzzers.
# All reuse the existing AFL testcase corpus and TIFF dictionary since
# they target the same TIFF file format.

for fuzzer in \
    tiff_read_strips_fuzzer \
    tiff_directory_fuzzer \
    tiff_rgba_oriented_fuzzer \
    tiff_codec_roundtrip_fuzzer; do
  cp "$OUT/tiff_read_rgba_fuzzer_seed_corpus.zip" \
     "$OUT/${fuzzer}_seed_corpus.zip"
  cp "$SRC/tiff.dict" "$OUT/${fuzzer}.dict"
done
