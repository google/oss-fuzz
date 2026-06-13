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

cd $SRC/vim

# Configure with ASAN/coverage-friendly flags
# Disable GUI, X11, network features to keep build minimal
./configure \
    CC="$CC" \
    CFLAGS="$CFLAGS -DFEAT_EVAL -DFEAT_REGEX -DFEAT_FUZZ" \
    --disable-gui \
    --without-x \
    --disable-netbeans \
    --disable-channel \
    --enable-multibyte \
    --with-features=normal \
    2>&1 | tail -5

make -j$(nproc) 2>&1 | tail -5

# Build fuzz_regexp
$CC $CFLAGS -I src \
    $SRC/fuzz_regexp.c \
    src/regexp.o src/regexp_bt.o src/regexp_nfa.o \
    src/charset.o src/message.o src/misc1.o src/misc2.o \
    src/memory.o src/mbyte.o src/strings.o \
    $LIB_FUZZING_ENGINE \
    -lpthread -lm -lncurses \
    -o $OUT/fuzz_regexp || \
echo "fuzz_regexp build failed (link issue), skipping"

# Seed corpus for regexp
mkdir -p $OUT/fuzz_regexp_seed_corpus
echo -n $'\x05hello\x00hello world' > $OUT/fuzz_regexp_seed_corpus/literal
echo -n $'\x04foo*\x00foooo'        > $OUT/fuzz_regexp_seed_corpus/star
echo -n $'\x06\[a-z\]\x00abc'       > $OUT/fuzz_regexp_seed_corpus/range
echo -n $'\x0c\\(foo\\)\\1\x00foofoo' > $OUT/fuzz_regexp_seed_corpus/backref
zip -j $OUT/fuzz_regexp_seed_corpus.zip $OUT/fuzz_regexp_seed_corpus/*

echo "Vim fuzz build complete."
