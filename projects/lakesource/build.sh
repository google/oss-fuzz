#!/usr/bin/env bash
# LakeSource E2 libFuzzer harness — OSS-Fuzz build script.
#
# Builds tools/fuzz/llvm_fuzzer_harness.cpp with -fsanitize=fuzzer,address
# against the minimal decoder closure of lakesource_runtime:
#
#   runtime/src/vtf_texture.cpp   (ParseVtfBytes)
#   runtime/src/net_client.cpp    (DecodeClientInputPacket / handshake decoders;
#                                  portable Win32/POSIX split, no sockets touched
#                                  on the pure-decode path)
#   runtime/src/replication.cpp   (DecodeEntitySnapshot / DecodePhysicsSnapshot)
#
# Headers come from runtime/include only (std-only). No other engine sources,
# no third-party deps, no downloads.
#
# OSS-Fuzz conventions honored: $CXX/$CXXFLAGS/$LIB_FUZZING_ENGINE from the
# base image, artifacts to $OUT (fuzzer binary + seed corpus zip named
# <fuzzer>_seed_corpus.zip). Do not add -fsanitize=fuzzer,address when
# LIB_FUZZING_ENGINE is set — CXXFLAGS already carries the sanitizer.
#
# Local smoke (outside OSS-Fuzz / helper.py), from the repo root:
#   CXX=clang++ CXXFLAGS="-O1 -g" OUT=out/oss-fuzz WORK=/tmp/lakesource-oss \
#     bash tools/fuzz/oss_fuzz/build.sh

set -eu

# Resolve the LakeSource checkout both ways it can be reached:
#  - inside OSS-Fuzz / helper.py, where this file is copied to $SRC/build.sh
#    and the local checkout is bind-mounted at $SRC/lakesource;
#  - in-repo, invoked directly as tools/fuzz/oss_fuzz/build.sh.
if [ -n "${SRC:-}" ] && [ -d "$SRC/lakesource/tools/fuzz/oss_fuzz" ]; then
    REPO="$SRC/lakesource"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO="$(cd "$SCRIPT_DIR/../../.." && pwd)"
fi

: "${CXX:?CXX must be set by OSS-Fuzz base-builder (clang++)}"
: "${CXXFLAGS:?CXXFLAGS must be set by OSS-Fuzz base-builder}"
: "${OUT:?OUT must point at the OSS-Fuzz artifact directory}"
: "${WORK:?WORK must point at the OSS-Fuzz scratch directory}"

mkdir -p "$OUT"

# Word-splitting of CXXFLAGS / LIB_FUZZING_ENGINE is the OSS-Fuzz contract.
# shellcheck disable=SC2086
if [ -n "${LIB_FUZZING_ENGINE:-}" ]; then
    "$CXX" $CXXFLAGS $LIB_FUZZING_ENGINE -std=c++20 \
        -I"$REPO/runtime/include" \
        "$REPO/tools/fuzz/llvm_fuzzer_harness.cpp" \
        "$REPO/runtime/src/vtf_texture.cpp" \
        "$REPO/runtime/src/net_client.cpp" \
        "$REPO/runtime/src/replication.cpp" \
        -o "$OUT/libfuzzer_parser_harness"
else
    "$CXX" $CXXFLAGS -std=c++20 -fsanitize=fuzzer,address \
        -I"$REPO/runtime/include" \
        "$REPO/tools/fuzz/llvm_fuzzer_harness.cpp" \
        "$REPO/runtime/src/vtf_texture.cpp" \
        "$REPO/runtime/src/net_client.cpp" \
        "$REPO/runtime/src/replication.cpp" \
        -o "$OUT/libfuzzer_parser_harness"
fi

# Seed corpus: byte-for-byte parity with tools/fuzz/run_parser_corpus.ps1
# (same New-SeedBytes values, same trunc/flip mutants, same file names) so a
# local run and the OSS-Fuzz upload start from identical inputs.
SEED_DIR="$WORK/lakesource_seed_corpus"
rm -rf "$SEED_DIR"
mkdir -p "$SEED_DIR"

python3 - "$SEED_DIR" <<'PYEOF'
import os, sys

out = sys.argv[1]
seeds = {
    "vtf": ("vtf", bytes([0x56, 0x54, 0x46, 0x00, 7, 0, 1, 0, 0xFF, 0xFF])),   # VTF\0 + junk
    "vpk": ("vpk", bytes([0x34, 0x12, 0xAA, 0x55, 1, 2, 3, 4])),
    "bsp": ("bsp", bytes([0x56, 0x42, 0x53, 0x50, 0, 0, 0, 0, 0xFF])),         # VBSP
    "mdl": ("mdl", bytes([0x49, 0x44, 0x53, 0x54, 1, 0, 0, 0, 0xEE])),         # IDST
    "net": ("lsci", bytes([0x4C, 0x53, 0x43, 0x49]) + bytes([0, 0, 0, 0, 9, 8, 7, 6])),  # LSCI
}

for kind, (ext, blob) in seeds.items():
    names = {
        "seed_%s.%s" % (kind, ext): blob,
        # trunc: first half, at least one byte (matches the ps1 runner).
        "mut_trunc_%s.%s" % (kind, ext): blob[: max(1, len(blob) // 2)],
        # flip: byte 0 xor 0xFF (matches the ps1 runner).
        "mut_flip_%s.%s" % (kind, ext):
            bytes([blob[0] ^ 0xFF]) + blob[1:],
    }
    for name, payload in names.items():
        with open(os.path.join(out, name), "wb") as handle:
            handle.write(payload)
PYEOF

# base-builder ships zip; fall back to python's zipfile elsewhere.
if command -v zip >/dev/null 2>&1; then
    zip -j -q "$OUT/libfuzzer_parser_harness_seed_corpus.zip" "$SEED_DIR"/*
else
    python3 - "$SEED_DIR" "$OUT/libfuzzer_parser_harness_seed_corpus.zip" <<'PYEOF'
import os, sys, zipfile

src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dst, "w", zipfile.ZIP_STORED) as archive:
    for name in sorted(os.listdir(src)):
        archive.write(os.path.join(src, name), name)
PYEOF
fi

echo "# LakeSource E2 harness built:"
echo "#   $OUT/libfuzzer_parser_harness"
echo "#   $OUT/libfuzzer_parser_harness_seed_corpus.zip"
