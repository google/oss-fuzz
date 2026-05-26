#!/bin/bash -eu
# Copyright 2025 Google LLC
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

cd $SRC/tz

# Build the TZif binary format parser fuzz target
$CC $CFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_tzif.c \
    localtime.c asctime.c difftime.c \
    -I. \
    -DTZDIR=\"/usr/share/zoneinfo\" \
    -o $OUT/fuzz_tzif

# Seed corpus: use real timezone files
mkdir -p $OUT/fuzz_tzif_seed_corpus
for f in /usr/share/zoneinfo/America/New_York \
          /usr/share/zoneinfo/Europe/London \
          /usr/share/zoneinfo/Asia/Tokyo \
          /usr/share/zoneinfo/UTC \
          /usr/share/zoneinfo/Pacific/Auckland; do
    [ -f "$f" ] && cp "$f" "$OUT/fuzz_tzif_seed_corpus/$(basename $f)" || true
done
zip -j $OUT/fuzz_tzif_seed_corpus.zip $OUT/fuzz_tzif_seed_corpus/* 2>/dev/null || true
