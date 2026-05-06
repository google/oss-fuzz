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
#   1. Builds tmux with the existing in-tree fuzzer (input-fuzzer)
#   2. Optionally builds additional harnesses from the tmux-oss-fuzz
#      project if it is present at $SRC/tmux-oss-fuzz
#   3. Generates the seed corpus for input-fuzzer

set -u

# Ensure libevent (built in the Dockerfile) is discoverable
export PKG_CONFIG_PATH="/usr/local/lib/"

cd "${SRC}/tmux"

# ---------------------------------------------------------------------------
# Step 1: Build tmux's in-tree fuzzer (input-fuzzer)
# ---------------------------------------------------------------------------

./autogen.sh

./configure \
    --enable-fuzzing \
    FUZZING_LIBS="${LIB_FUZZING_ENGINE} -lc++" \
    LIBEVENT_LIBS="-Wl,-Bstatic -levent -Wl,-Bdynamic" \
    LIBTINFO_LIBS=" -l:libtinfo.a "

make -j"$(nproc)" check

# Copy the in-tree fuzzer artifacts to $OUT
find "${SRC}/tmux/fuzz/" -name '*-fuzzer'         -exec cp -v '{}' "${OUT}/" \;
find "${SRC}/tmux/fuzz/" -name '*-fuzzer.options' -exec cp -v '{}' "${OUT}/" \;
find "${SRC}/tmux/fuzz/" -name '*-fuzzer.dict'    -exec cp -v '{}' "${OUT}/" \;

# ---------------------------------------------------------------------------
# Step 2: Build additional harnesses from tmux-oss-fuzz (optional)
# ---------------------------------------------------------------------------
#
# When this project is cloned alongside tmux into $SRC, build the extra
# harnesses against tmux's already-compiled object files. Each harness is
# emitted as a separate fuzz target named "<target>-<type>".

EXTRA_DIR="${SRC}/tmux-oss-fuzz"
if [ -d "${EXTRA_DIR}/harnesses" ]; then
    echo "Building additional harnesses from ${EXTRA_DIR}..."

    # tmux object files. INCLUDE tmux.o because tmux's build under
    # --enable-fuzzing marks main() as weak so libFuzzer's main wins;
    # tmux.o also provides global helpers (clean_name, etc.) that the
    # other tmux objects reference.
    # Exclude only the in-tree fuzzer objects (their own
    # LLVMFuzzerTestOneInput would clash with ours).
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

        echo "  Building ${out_name}..."
        $CC $CFLAGS \
            -I"${SRC}/tmux" \
            "${src}" \
            ${TMUX_OBJS} \
            ${LIB_FUZZING_ENGINE} \
            -levent -lncurses -lutil -lm -lresolv \
            -o "${OUT}/${out_name}" \
            || echo "    FAILED: ${out_name}"
    }

    # Derive a canonical target name from a harness basename.
    # Categories are inferred from the directory, so we just strip
    # the trailing per-category/per-style suffix from the filename.
    derive_target() {
        local base="$1"
        # Strip category suffix
        case "${base}" in
            *-manual)   base="${base%-manual}" ;;
            *-llm)      base="${base%-llm}" ;;
            *-fuzzgen)  base="${base%-fuzzgen}" ;;
        esac
        # Strip trailing -fuzzer (manual harnesses are sometimes named
        # "<target>-fuzzer.c", and a few are "<target>-fuzzer-<cat>.c").
        base="${base%-fuzzer}"
        # Normalize: input/input-fuzzer all refer to input-parse target
        case "${base}" in
            input|input-fuzzer) base="input-parse" ;;
        esac
        echo "${base}"
    }

    for category_dir in "${EXTRA_DIR}/harnesses/manual" \
                        "${EXTRA_DIR}/harnesses/llm_generated" \
                        "${EXTRA_DIR}/harnesses/fuzzgen_generated"; do
        [ -d "${category_dir}" ] || continue
        category=$(basename "${category_dir}" | sed 's/_generated//')

        for harness in "${category_dir}"/*.c; do
            [ -f "${harness}" ] || continue
            base=$(basename "${harness}" .c)
            target=$(derive_target "${base}")
            build_harness "${harness}" "${target}-${category}"
        done
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

        # Use tmux's built-in test scripts as seeds
        bash "${SRC}/tmux/tools/24-bit-color.sh" 2>/dev/null | \
            split -a4 -db"${MAXLEN}" - 24-bit-color.out. || true
        perl "${SRC}/tmux/tools/256colors.pl"    2>/dev/null | \
            split -a4 -db"${MAXLEN}" - 256colors.out.    || true
        cat "${SRC}/tmux/tools/UTF-8-demo.txt"   2>/dev/null | \
            split -a4 -db"${MAXLEN}" - UTF-8-demo.txt.   || true

        # External terminal-emulator test sequences (shipped via tmux-fuzzing-corpus)
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
