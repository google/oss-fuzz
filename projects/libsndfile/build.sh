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

# Run the OSS-Fuzz script in the project.
apt-get update
./ossfuzz/ossfuzz.sh

# To make CIFuzz fast, see here for details: https://github.com/libsndfile/libsndfile/pull/796
for fuzzer in sndfile_alt_fuzzer sndfile_fuzzer sndfile_fmt_fuzzer; do
  echo "[libfuzzer]" > ${OUT}/${fuzzer}.options
  echo "close_fd_mask = 3" >> ${OUT}/${fuzzer}.options
done

# Seed corpus for the format fuzzer
fmtseed="$SRC/fmt_seeds"
mkdir -p "$fmtseed"
for i in 0 1 2 3 4 5 6 7; do
  printf "\\x0$i" > "$fmtseed/sel_$i"
  head -c 512 /dev/urandom >> "$fmtseed/sel_$i"
done
zip -j -q "$OUT/sndfile_fmt_fuzzer_seed_corpus.zip" "$fmtseed"/*
