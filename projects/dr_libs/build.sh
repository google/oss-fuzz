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

mkdir -p "$WORK/build"
cd "$WORK/build"
cmake -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
      -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DDR_LIBS_BUILD_FUZZERS=ON \
      "$SRC/dr_libs"
make -j"$(nproc)"

cp dr_wav_fuzzer dr_flac_fuzzer dr_mp3_fuzzer "$OUT/"

git clone --depth 1 https://github.com/timblechmann/dr_libs-fuzzing-corpus.git "$SRC/dr_libs-fuzzing-corpus"
find "$SRC/dr_libs-fuzzing-corpus/wav" -type f -exec zip -jq "$OUT/dr_wav_fuzzer_seed_corpus.zip" {} +
find "$SRC/dr_libs-fuzzing-corpus/flac" -type f -exec zip -jq "$OUT/dr_flac_fuzzer_seed_corpus.zip" {} +
find "$SRC/dr_libs-fuzzing-corpus/mp3" -type f -exec zip -jq "$OUT/dr_mp3_fuzzer_seed_corpus.zip" {} +
