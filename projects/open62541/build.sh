#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

# LOGLEVEL:
# <= 100 TRACE
# <= 200 DEBUG
# <= 300 INFO
# <= 400 WARNING
# <= 500 ERROR
# <= 600 FATAL
# > 600 No LOG output

# Build all fuzz targets for a given open62541 source tree.
#
# Arguments:
#   SRC_DIR  - path to the open62541 source checkout
#   SUFFIX   - binary name suffix (empty for master, "_15" for the 1.5 branch).
#              When non-empty, cmake outputs to a temporary directory and the
#              resulting binaries are copied into $OUT with the suffix appended.
function build_open62541_fuzzers() {
    local SRC_DIR=$1
    local SUFFIX=$2

    # Use a separate cmake build directory per source tree
    local WORK_DIR="$WORK/open62541${SUFFIX}"
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"

    # When a suffix is requested we build into a temporary output directory so
    # that binaries from different branches do not overwrite each other in $OUT.
    local OUT_DIR="$OUT"
    if [[ -n "$SUFFIX" ]]; then
        OUT_DIR="$WORK/out${SUFFIX}"
        mkdir -p "$OUT_DIR"
    fi

    # cmake reads $OUT at configuration time to set CMAKE_RUNTIME_OUTPUT_DIRECTORY
    OUT="$OUT_DIR" cmake \
        -DCMAKE_BUILD_TYPE=Debug \
        -DUA_ENABLE_AMALGAMATION=OFF \
        -DPYTHON_EXECUTABLE:FILEPATH=/usr/bin/python3 \
        -DBUILD_SHARED_LIBS=OFF \
        -DUA_BUILD_EXAMPLES=OFF \
        -DUA_LOGLEVEL=600 \
        -DUA_ENABLE_ENCRYPTION=ON \
        -DUA_BUILD_OSS_FUZZ=ON \
        "$SRC_DIR/"

    # Only build with one process otherwise amalgamation fails.
    make -j1

    # For suffixed builds, copy every compiled fuzzer binary into the real $OUT
    # with the suffix appended to the binary name.
    if [[ -n "$SUFFIX" ]]; then
        for f in "$OUT_DIR"/*; do
            [[ -f "$f" && -x "$f" ]] || continue
            fname=$(basename "$f")
            cp "$f" "$OUT/${fname}${SUFFIX}"
        done
    fi

    # --- Corpus, options, and dict handling ---
    # Replaces the inline oss-fuzz-copy.sh call so that paths and suffixes can
    # be parameterised.

    # Seed corpora: one zip per fuzzer that has a corpus directory
    fuzzerFiles=$(find "$SRC_DIR/tests/fuzz/" -maxdepth 1 -name "*.cc")
    for F in $fuzzerFiles; do
        fuzzerName=$(basename "$F" .cc)
        corpusDir="$SRC_DIR/tests/fuzz/${fuzzerName}_corpus"
        if [[ -d "$corpusDir" ]]; then
            zip -jr "$OUT/${fuzzerName}${SUFFIX}_seed_corpus.zip" "$corpusDir/"
        fi
    done

    # fuzz_tcp_message reuses the fuzz_binary_message corpus
    if [[ -f "$OUT/fuzz_binary_message${SUFFIX}_seed_corpus.zip" ]]; then
        cp "$OUT/fuzz_binary_message${SUFFIX}_seed_corpus.zip" \
           "$OUT/fuzz_tcp_message${SUFFIX}_seed_corpus.zip"
    fi

    # Options files: copy and rename to match the (potentially suffixed) binary
    for optFile in "$SRC_DIR/tests/fuzz/"*.options; do
        [[ -f "$optFile" ]] || continue
        base=$(basename "$optFile" .options)
        cp "$optFile" "$OUT/${base}${SUFFIX}.options"
    done

    # Dict files: the options files reference them by their original name so no
    # renaming is necessary.  A later build will simply overwrite with the same
    # content, which is harmless.
    for dictFile in "$SRC_DIR/tests/fuzz/"*.dict; do
        [[ -f "$dictFile" ]] || continue
        cp "$dictFile" "$OUT/"
    done

    # Copy corpus / dict / options from the bundled mdnsd dependency, if
    # the submodule is present and its copy script exists.
    local mdns_copy="$SRC_DIR/deps/mdnsd/tests/fuzz/oss-fuzz-copy.sh"
    if [[ -f "$mdns_copy" ]]; then
        SRC="$SRC_DIR/deps" "$mdns_copy"
    fi
}

# ── Master branch (no suffix) ────────────────────────────────────────────────
build_open62541_fuzzers "$SRC/open62541" ""

# In introspector mode only the master branch is needed.
if [[ "$SANITIZER" == introspector ]]; then
    echo "Introspector mode: skipping 1.5 branch build."
    exit 0
fi

# ── 1.5 branch (_15 suffix) ──────────────────────────────────────────────────
build_open62541_fuzzers "$SRC/open62541_15" "_15"

echo "Built all fuzzer targets."
