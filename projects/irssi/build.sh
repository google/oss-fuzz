#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# setup
BUILD=$WORK/Build
fuzz_targets=(
    src/fe-fuzz/irssi-fuzz
    src/fe-fuzz/server-fuzz
    src/fe-fuzz/irc/core/event-get-params-fuzz
    src/fe-fuzz/fe-common/core/theme-load-fuzz
)

if [ "$FUZZING_ENGINE" = honggfuzz ]; then
    export CC="$SRC"/"$FUZZING_ENGINE"/hfuzz_cc/hfuzz-clang
    export CXX="$SRC"/"$FUZZING_ENGINE"/hfuzz_cc/hfuzz-clang++
fi

# cleanup
rm -rf "$BUILD"
mkdir -p "$BUILD"

# Configure the project.
meson "$BUILD" -Dstatic-dependency=yes -Dinstall-glib=force \
      -Dwith-fuzzer=yes -Dwith-fuzzer-lib=$LIB_FUZZING_ENGINE \
      -Dfuzzer-link-language=cpp \
    || ( cat "$BUILD"/meson-logs/meson-log.txt && false )

# now build all fuzz targets
ninja -C "$BUILD" -v "${fuzz_targets[@]}"
( cd "$BUILD" && mv "${fuzz_targets[@]}" "$OUT" )

git clone --depth 1 https://github.com/irssi-import/themes         theme-load-fuzz_corpus
git clone --depth 1 https://github.com/irssi/irssi-fuzzing-corpora

find theme-load-fuzz_corpus -mindepth 1 -maxdepth 1 \( -type d -o \! -name \*.theme \) -exec rm -fr {} +

zip -q -j "$OUT"/theme-load-fuzz_seed_corpus.zip theme-load-fuzz_corpus/*
zip -q -j "$OUT"/irssi-fuzz_seed_corpus.zip      irssi-fuzzing-corpora/irssi-fuzz-corpus/*
zip -q -j "$OUT"/server-fuzz_seed_corpus.zip     irssi-fuzzing-corpora/server-fuzz-corpus/*

# get tokens.txt dictionary from irssi/src/fe-fuzz/
cp src/fe-fuzz/tokens.txt "$OUT"/server-fuzz.dict

cp "$SRC"/*.options "$SRC"/*.dict "$OUT"/
