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
# OSS-Fuzz build script for ts-transformer.
#
# Invoked inside the OSS-Fuzz base-builder-rust container by:
#   docker run -v $OUT:/out -e SANITIZER=address \
#     gcr.io/oss-fuzz/ts-transformer compile
#
# Responsibilities:
#   1. Build every cargo-fuzz harness in the tree (tst-core, tst-rtp,
#      tst-srt — the count is asserted against the fuzz_targets/*.rs
#      inventory at the end of this script, so it cannot silently drift)
#      under libFuzzer with the SANITIZER env-var honored by cargo-fuzz.
#   2. Copy each driver binary to $OUT/<target_name>.
#
# Seed corpora, dictionaries, and .options files are emitted in later
# build.sh revisions — see oss-fuzz/README.md.
set -euo pipefail

# Vendored libsrt + mbedTLS build path, matches CI.
export SRT_FORCE_VENDORED=1

# The OSS-Fuzz base image pins its nightly through RUSTUP_TOOLCHAIN, which
# takes precedence over the workspace's rust-toolchain.toml (stable 1.85 —
# no -Zsanitizer). Outside the image fall back to the local `nightly`. A
# literal `cargo +nightly` would ignore the image's pin and auto-install
# whatever nightly is current, so the toolchain is selected here instead.
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"

# cargo-fuzz target dir (per cargo-fuzz convention).
TARGET_DIR=target/x86_64-unknown-linux-gnu/release

# Build tst-core fuzz targets.
pushd crates/tst-core
cargo fuzz build --release
popd

# Build tst-rtp fuzz targets.
pushd crates/tst-rtp
cargo fuzz build --release
popd

# Build tst-srt fuzz targets.
pushd crates/tst-srt
cargo fuzz build --release
popd

# Copy fuzz drivers to $OUT/, counting executable drivers only (corpora,
# dictionaries, and .options are packaged separately below and must not
# inflate the driver count).
shipped_drivers=0
expected_drivers=0
for crate_dir in crates/tst-core crates/tst-rtp crates/tst-srt; do
  for target_src in "$crate_dir"/fuzz/fuzz_targets/*.rs; do
    expected_drivers=$((expected_drivers + 1))
    target_name=$(basename "$target_src" .rs)
    bin_path="$crate_dir/fuzz/$TARGET_DIR/$target_name"
    if [ -x "$bin_path" ]; then
      cp "$bin_path" "$OUT/$target_name"
      shipped_drivers=$((shipped_drivers + 1))
    else
      echo "ERROR: $crate_dir fuzz binary missing for $target_name (expected $bin_path)"
    fi
  done
done

# Copy per-target .options files where present.
for options_file in oss-fuzz/targets/*.options; do
  [ -f "$options_file" ] || continue
  options_name=$(basename "$options_file")
  cp "$options_file" "$OUT/$options_name"
done


# Copy the shared KLV dictionary if present.
if [ -f oss-fuzz/targets/klv.dict ]; then
  # libFuzzer's -dict flag takes a single file. Each KLV target gets the
  # dict via its corresponding .options file's `dict = ` line — but since
  # we ship one dict and want it picked up automatically, naming it
  # <target>.dict makes libFuzzer find it without an explicit option.
  for tgt in klv_st0601_decode klv_st0102_decode klv_st0903_decode; do
    cp oss-fuzz/targets/klv.dict "$OUT/${tgt}.dict"
  done
fi

# Seed corpus packaging — unified loop.
#
# Per-target precedence (zip merges all sources for a target):
#   1. crates/tst-core/tests/fixtures/<source>/  (fixture-derived; do not edit)
#   2. crates/<crate>/fuzz/seeds/<target>/       (committed synthetic seeds — single source of truth)

# Helper: zip-or-append for a single target.
zip_seeds() {
  local target="$1"; shift
  local out_zip="$OUT/${target}_seed_corpus.zip"
  for src_dir in "$@"; do
    if [ -d "$src_dir" ] && ls "$src_dir"/* >/dev/null 2>&1; then
      (cd "$src_dir" && zip -j -q "$out_zip" *)
    fi
  done
}

# Fixture-derived seeds.
zip_seeds klv_st0601_decode      crates/tst-core/tests/fixtures/st0601
zip_seeds demux_feed             crates/tst-core/tests/fixtures/regression
zip_seeds demux_psi              crates/tst-core/tests/fixtures/regression
zip_seeds demux_pes_reassembly   crates/tst-core/tests/fixtures/regression
zip_seeds ts_parser              crates/tst-core/tests/fixtures/regression

# Committed synthetic seeds — canonical under crates/<crate>/fuzz/seeds/<target>/.
zip_seeds mpegts_au_cell_read       crates/tst-core/fuzz/seeds/mpegts_au_cell_read
zip_seeds audio_frame_iter          crates/tst-core/fuzz/seeds/audio_frame_iter
zip_seeds url_parse                 crates/tst-srt/fuzz/seeds/url_parse
zip_seeds mux_pull                  crates/tst-core/fuzz/seeds/mux_pull
zip_seeds mux_push_klv              crates/tst-core/fuzz/seeds/mux_push_klv
zip_seeds mux_push_video            crates/tst-core/fuzz/seeds/mux_push_video
zip_seeds parse_parameter_sets      crates/tst-core/fuzz/seeds/parse_parameter_sets
zip_seeds parse_av1_sequence_header crates/tst-core/fuzz/seeds/parse_av1_sequence_header

# Assert every declared harness shipped as an executable driver. This
# counts drivers only — NOT the corpora/dict/options files above — so a
# fuzz-target addition that build.sh fails to bundle breaks the build
# loudly instead of shipping a silently smaller fleet.
echo "INFO: shipped $shipped_drivers/$expected_drivers fuzz drivers to \$OUT"
if [ "$shipped_drivers" -ne "$expected_drivers" ]; then
  echo "ERROR: driver count mismatch — expected $expected_drivers (one per fuzz_targets/*.rs), shipped $shipped_drivers"
  exit 1
fi
