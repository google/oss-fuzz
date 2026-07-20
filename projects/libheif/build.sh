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

# Delegate actual building to the script provided by libheif.
./scripts/build-oss-fuzz.sh

# Structured HEIF/ISOBMFF seeds (see generate_seeds.py). These exercise the
# box / item-property / derivation (grid, iovl) parsing in box.cc and the
# movie-box path in seq_boxes.cc that the shipped .heic corpus does not carry.
# box_fuzzer and tile_fuzzer ship no corpus at all, so they gain the most.
python3 "$SRC/generate_seeds.py" "$SRC/generated_heif_seeds"

# Name corpora with the underscore convention OSS-Fuzz actually loads
# (<fuzz_target>_seed_corpus.zip); the binaries are file_fuzzer / box_fuzzer /
# tile_fuzzer.
zip -j -q "$OUT/box_fuzzer_seed_corpus.zip" "$SRC"/generated_heif_seeds/*.heif
zip -j -q "$OUT/tile_fuzzer_seed_corpus.zip" "$SRC"/generated_heif_seeds/*.heif
# file_fuzzer: the stock .heic corpus plus the generated container seeds.
cp "$SRC"/libheif/fuzzing/data/corpus/*.heic "$SRC"/generated_heif_seeds/ 2>/dev/null || true
zip -j -q "$OUT/file_fuzzer_seed_corpus.zip" "$SRC"/generated_heif_seeds/*
