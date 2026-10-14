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
#
# OSS-Fuzz build script for tmux.
#
# This script:
#   1. Builds tmux from upstream master with the existing in-tree fuzzers
#      (input-fuzzer, cmd-parse-fuzzer, format-fuzzer, style-fuzzer).
#   2. Builds 6 additional, hand-picked harnesses from the tmux-oss-fuzz
#      project — one per parser/processing surface that achieved the
#      best evaluation coverage.
#   3. Generates the seed corpus for input-fuzzer.

set -u

export PKG_CONFIG_PATH="/usr/local/lib/"

cd "${SRC}/tmux"

# ---------------------------------------------------------------------------
# Step 1: Build tmux's in-tree fuzzers
# ---------------------------------------------------------------------------
./autogen.sh

./configure \
    --enable-fuzzing \
    FUZZING_LIBS="${LIB_FUZZING_ENGINE} -lc++" \
    LIBEVENT_LIBS="-Wl,-Bstatic -levent -Wl,-Bdynamic" \
    LIBTINFO_LIBS=" -l:libtinfo.a "

make -j"$(nproc)" check

find "${SRC}/tmux/fuzz/" -name '*-fuzzer'         -exec cp -v '{}' "${OUT}/" \;
find "${SRC}/tmux/fuzz/" -name '*-fuzzer.options' -exec cp -v '{}' "${OUT}/" \;
find "${SRC}/tmux/fuzz/" -name '*-fuzzer.dict'    -exec cp -v '{}' "${OUT}/" \;

# ---------------------------------------------------------------------------
# Step 2: Build the additional best-of-breed harnesses
# ---------------------------------------------------------------------------
# Each entry below is the single best harness for its target, chosen
# from the comparative evaluation in tmux-oss-fuzz/docs/results.md.
# Format: "<source-relative-path-under-harnesses/> <output-target-name>".

EXTRA_DIR="${SRC}/tmux-oss-fuzz"
if [ -d "${EXTRA_DIR}/harnesses" ]; then
    echo "Building additional best-of-breed harnesses from ${EXTRA_DIR}..."

    # All tmux objects. We INCLUDE tmux.o because tmux's
    # --enable-fuzzing path marks main() as weak so libFuzzer's main
    # wins, and tmux.o provides global helpers used by other objects.
    # Exclude in-tree fuzzer objects (they each define their own
    # LLVMFuzzerTestOneInput which would collide).
    TMUX_OBJS=$(find "${SRC}/tmux" -name "*.o" \
        ! -path "*/fuzz/*" \
        | tr '\n' ' ')

    if [ -z "${TMUX_OBJS}" ]; then
        echo "ERROR: no tmux object files found; tmux build may have failed" >&2
        exit 1
    fi

    build_harness() {
        local src="$1"
        local out_name="$2"

        if [ ! -f "${src}" ]; then
            echo "  SKIP ${out_name}: source missing (${src})"
            return
        fi
        echo "  Building ${out_name}..."
        $CC $CFLAGS \
            -I"${SRC}/tmux" \
            "${src}" \
            ${TMUX_OBJS} \
            ${LIB_FUZZING_ENGINE} \
            -levent -lncurses -lutil -lm -lresolv \
            -o "${OUT}/${out_name}"
    }

    # One harness per target.
    for harness in input-parse  cmd-parse  layout-parse  utf8  format  style; do
        build_harness "${EXTRA_DIR}/harnesses/${harness}-fuzzer-extra.c" \
                      "${harness}-fuzzer-extra"
    done
fi

# ---------------------------------------------------------------------------
# Step 3: Build seed corpus for input-fuzzer
# ---------------------------------------------------------------------------
OPTIONS_FILE="${OUT}/input-fuzzer.options"
if [ -f "${OPTIONS_FILE}" ]; then
    MAXLEN=$(grep -Po 'max_len\s*=\s*\K\d+' "${OPTIONS_FILE}" || echo "8192")

    if [ ! -d "${WORK}/fuzzing_corpus" ]; then
        mkdir "${WORK}/fuzzing_corpus"
        cd "${WORK}/fuzzing_corpus"

        bash "${SRC}/tmux/tools/24-bit-color.sh" 2>/dev/null | \
            split -a4 -db"${MAXLEN}" - 24-bit-color.out. || true
        perl "${SRC}/tmux/tools/256colors.pl"    2>/dev/null | \
            split -a4 -db"${MAXLEN}" - 256colors.out.    || true
        cat "${SRC}/tmux/tools/UTF-8-demo.txt"   2>/dev/null | \
            split -a4 -db"${MAXLEN}" - UTF-8-demo.txt.   || true

        if [ -d "${SRC}/tmux-fuzzing-corpus" ]; then
            for src_dir in alacritty esctest iterm2; do
                [ -d "${SRC}/tmux-fuzzing-corpus/${src_dir}" ] || continue
                cat "${SRC}/tmux-fuzzing-corpus/${src_dir}"/* 2>/dev/null | \
                    split -a5 -db"${MAXLEN}" - "${src_dir}." || true
            done
        fi

        zip -q -j -r "${OUT}/input-fuzzer_seed_corpus.zip" \
            "${WORK}/fuzzing_corpus/"
    fi
fi

# Seed corpus for the layout fuzzer.
mkdir -p "${WORK}/layout_corpus"
python3 - "${WORK}/layout_corpus" <<'EOF'
import os
import sys


def checksum(body):
    csum = 0
    for ch in body.encode():
        csum = ((csum >> 1) + ((csum & 1) << 15)) & 0xFFFF
        csum = (csum + ch) & 0xFFFF
    return csum


bodies = [
    "80x24,0,0{20x24,0,0,0,19x24,21,0,3,19x24,41,0,2,19x24,61,0,1}",
    "80x24,0,0[80x6,0,0,4,80x5,0,7,7,80x5,0,13,6,80x5,0,19,5]",
    "80x24,0,0[80x22,0,0,8,80x1,0,23{26x1,0,23,11,26x1,27,23,10,26x1,54,23,9}]",
    "80x24,0,0[80x1,0,0{26x1,0,0,15,26x1,27,0,14,26x1,54,0,13},80x22,0,2,12]",
    "80x24,0,0{78x24,0,0,16,1x24,79,0[1x8,79,0,19,1x7,79,9,18,1x7,79,17,17]}",
    "80x24,0,0{1x24,0,0[1x8,0,0,23,1x7,0,9,22,1x7,0,17,21],78x24,2,0,20}",
    "80x24,0,0[80x11,0,0{39x11,0,0,24,40x11,40,0,27},80x12,0,12{39x12,0,12,26,40x12,40,12,25}]",
]

for i, body in enumerate(bodies):
    path = os.path.join(sys.argv[1], "layout_%d" % i)
    with open(path, "w") as f:
        f.write("%04x,%s" % (checksum(body), body))
EOF
zip -q -j -r "${OUT}/layout-fuzzer_seed_corpus.zip" "${WORK}/layout_corpus/"
