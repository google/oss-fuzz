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

    # The "best of breed" set: one harness per target, chosen by coverage.
    #   target            picked variant      output name
    #   ----------------  -----------------   ------------
    build_harness "${EXTRA_DIR}/harnesses/llm_generated/input-parse-llm.c"   input-parse-fuzzer-extra
    build_harness "${EXTRA_DIR}/harnesses/llm_generated/cmd-parse-llm.c"     cmd-parse-fuzzer-extra
    build_harness "${EXTRA_DIR}/harnesses/manual/layout-parse-fuzzer.c"      layout-parse-fuzzer-extra
    build_harness "${EXTRA_DIR}/harnesses/manual/utf8-fuzzer.c"              utf8-fuzzer-extra
    build_harness "${EXTRA_DIR}/harnesses/manual/format-fuzzer.c"            format-fuzzer-extra
    build_harness "${EXTRA_DIR}/harnesses/llm_generated/style-llm.c"         style-fuzzer-extra
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
