#!/bin/bash -eu
# Copyright 2020 Google LLC
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

# Ensure libevent can be found
export PKG_CONFIG_PATH="/usr/local/lib/"

./autogen.sh
./configure \
    --enable-fuzzing \
    FUZZING_LIBS="${LIB_FUZZING_ENGINE} -lc++" \
    LIBEVENT_LIBS="-Wl,-Bstatic -levent -Wl,-Bdynamic" \
    LIBTINFO_LIBS=" -l:libtinfo.a "

make -j"$(nproc)" check
find "${SRC}/tmux/fuzz/" -name '*-fuzzer' -exec cp -v '{}' "${OUT}"/ \;
find "${SRC}/tmux/fuzz/" -name '*-fuzzer.options' -exec cp -v '{}' "${OUT}"/ \;
find "${SRC}/tmux/fuzz/" -name '*-fuzzer.dict' -exec cp -v '{}' "${OUT}"/ \;

MAXLEN=$(grep -Po 'max_len\s+=\s+\K\d+' "${OUT}/input-fuzzer.options")
mkdir "${WORK}/fuzzing_corpus"
cd "${WORK}/fuzzing_corpus"
bash "${SRC}/tmux/tools/24-bit-color.sh" | \
    split -a4 -db$MAXLEN - 24-bit-color.out.
perl "${SRC}/tmux/tools/256colors.pl" | \
    split -a4 -db$MAXLEN - 256colors.out.
cat "${SRC}/tmux/tools/UTF-8-demo.txt" | \
    split -a4 -db$MAXLEN - UTF-8-demo.txt.
cat "${SRC}/tmux-fuzzing-corpus/alacritty"/* | \
    split -a4 -db$MAXLEN - alacritty.
cat "${SRC}/tmux-fuzzing-corpus/esctest"/* | \
    split -a4 -db$MAXLEN - esctest.
cat "${SRC}/tmux-fuzzing-corpus/iterm2"/* | \
    split -a5 -db$MAXLEN - iterm2.
zip -q -j -r "${OUT}/input-fuzzer_seed_corpus.zip" \
    "${WORK}/fuzzing_corpus/"
