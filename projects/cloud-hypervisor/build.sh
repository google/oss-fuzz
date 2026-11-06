# Copyright 2022 Google LLC
# Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
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
set -euo pipefail

: "${OUT:?OUT must name the OSS-Fuzz output directory}"
SANITIZER=${SANITIZER:-address}
QEMU_IMG=${QEMU_IMG:-qemu-img}
RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-nightly}
export RUSTUP_TOOLCHAIN
BUILD_DIR=fuzz/target/x86_64-unknown-linux-gnu/release
STAGE_DIR=$(mktemp -d)
WORK_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$STAGE_DIR" "$WORK_DIR"
}
trap cleanup EXIT

case "$SANITIZER" in
address|leak|memory|thread|none) FUZZ_SANITIZER=$SANITIZER ;;
coverage) FUZZ_SANITIZER=none ;;
*) echo "error: unsupported SANITIZER=$SANITIZER" >&2; exit 1 ;;
esac

cd "$SRC/cloud-hypervisor"
mkdir -p "$OUT"

build_targets() {
    cargo fuzz build -O --sanitizer "$FUZZ_SANITIZER"
}

stage_binaries() {
    local source target

    for source in fuzz/fuzz_targets/*.rs; do
        target=$(basename "${source%.rs}")
        if [[ ! -x "$BUILD_DIR/$target" ]]; then
            echo "error: cargo-fuzz did not produce $BUILD_DIR/$target" >&2
            exit 1
        fi
        cp "$BUILD_DIR/$target" "$STAGE_DIR/$target"
    done
}

stage_disk_corpora() {
    local corpus="$WORK_DIR/corpus"
    local target directory

    if ! command -v "$QEMU_IMG" >/dev/null 2>&1; then
        echo "error: $QEMU_IMG not found; install qemu-utils before generating disk seeds" >&2
        exit 1
    fi
    scripts/generate-fuzz-seeds.sh "$corpus"

    # Explicit input budgets, not rounded seed sizes.
    declare -A max_len=(
        [disk_detect]=16777216
        [disk_qcow2]=2097152
        [disk_qcow2_chain]=4194312
        [disk_vhd]=4194304
        [disk_vhdx]=16777216
        [disk_vmdk]=1048577
    )
    for target in "${!max_len[@]}"; do
        directory="$corpus/$target"
        if [[ ! -d "$directory" ]] || [[ -z "$(find "$directory" -type f -print -quit)" ]]; then
            echo "error: seed generator did not produce a non-empty $target corpus" >&2
            exit 1
        fi
        (cd "$directory" && zip -q -r "$STAGE_DIR/${target}_seed_corpus.zip" .)
        printf '[libfuzzer]\nmax_len = %s\n' "${max_len[$target]}" >"$STAGE_DIR/$target.options"
    done
}

stage_dictionaries() {
    local format source target

    for format in qcow2 qcow2_chain vhd vhdx vmdk; do
        source="fuzz/dictionaries/$format.dict"
        target="disk_$format"
        if [[ ! -s "$source" ]]; then
            echo "error: missing dictionary $source" >&2
            exit 1
        fi
        if [[ ! -x "$BUILD_DIR/$target" ]]; then
            echo "error: dictionary target $target was not built" >&2
            exit 1
        fi
        cp "$source" "$STAGE_DIR/$target.dict"
    done
}

build_targets
stage_binaries
stage_disk_corpora
stage_dictionaries

# Copy only the artifacts produced by this invocation; never recursively remove
# files from OUT, which may be shared with the surrounding OSS-Fuzz build.
cp "$STAGE_DIR"/* "$OUT/"
echo "staged fuzz targets, disk corpora and metadata in $OUT"
