#!/bin/bash -eu
# Copyright 2021 Google LLC
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

CH_SRC="$SRC/ClickHouse"
CH_BUILD="$WORK/clickhouse"


# Number of fuzz targets built when OSS_FUZZ_CI=1.
CI_TARGET_LIMIT=2

mkdir -p "$CH_BUILD" && cd "$CH_BUILD"
rm -rf "${OUT:?}"/*

rm -f CMakeCache.txt

# ClickHouse uses libcxx from contrib.
# Enabling libstdc++ manually will cause duplicate symbols at linker stage.
# Plus we want to fuzz the same binary as we have in our CI
# https://github.com/ClickHouse/ClickHouse/blob/2e2ef087129ed072404bdc084e8028a5c5869dc0/PreLoad.cmake#L23
unset CFLAGS
unset CXXFLAGS
unset LDFLAGS

# ClickHouse builds `protoc` from sources to be dependent only on compiler
# but if we build ClickHouse with any kind of sanitizer, then `protoc`
# will be built with sanitizer too...
# Protoc will be used during ClickHouse builds to generate .cpp sources from .proto files
# and everything works in our CI, but not here...
# We use libprotobuf-mutator and self-written script to generate SQL-based AST from mutated .proto
# Maybe some of proto files are too complex and this is the cause of `protoc` failures
# So, this flag only helps to supress error from `protoc` built with any kind of sanitizer
export MSAN_OPTIONS=exit_code=0


NUM_JOBS=$(nproc || grep -c ^processor /proc/cpuinfo)

if (( NUM_JOBS > 10 )); then
    NUM_JOBS=$((NUM_JOBS / 4))
fi

CLICKHOUSE_CMAKE_FLAGS=(
    "-DCMAKE_CXX_COMPILER_LAUNCHER=/usr/bin/ccache"
    "-DCMAKE_C_COMPILER=$CC"
    "-DCMAKE_CXX_COMPILER=$CXX"
    "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
    "-DLIB_FUZZING_ENGINE:STRING=$LIB_FUZZING_ENGINE"
    "-DENABLE_FUZZING=1"
    "-DENABLE_PROTOBUF=1"
    "-DPARALLEL_COMPILE_JOBS=$NUM_JOBS"
)

if [ "$SANITIZER" = "coverage" ]; then
    CLICKHOUSE_CMAKE_FLAGS+=("-DWITH_COVERAGE=1")
else
    CLICKHOUSE_CMAKE_FLAGS+=("-DSANITIZE=$SANITIZER")
fi

cmake -G Ninja "$CH_SRC" "${CLICKHOUSE_CMAKE_FLAGS[@]}"

# Fuzz targets are the *_fuzzer.cpp files under src and programs. Only the ones
# the configured build actually defines are built: some are optional (for example
# sz3_decompress_fuzzer needs the SZ3 contrib), and a missing target is not an error.
CONFIGURED_TARGETS="$CH_BUILD/oss_fuzz_targets.txt"
ninja -t targets all > "$CONFIGURED_TARGETS"

TARGETS=()
while IFS= read -r FUZZER_TARGET; do
    if grep -Eq "^([^:]*/)?${FUZZER_TARGET}: " "$CONFIGURED_TARGETS"; then
        TARGETS+=("$FUZZER_TARGET")
    else
        echo "Skipping $FUZZER_TARGET: not defined by this configuration"
    fi
done < <(cd "$CH_SRC" && find src programs -type f -name '*_fuzzer.cpp' ! -name 'gtest_*' -exec basename {} .cpp ';' | LC_ALL=C sort -u)

if [ "${OSS_FUZZ_CI-}" = "1" ]; then
    # Explicit CI mode checks the first targets only to save time and disk space.
    TARGETS=("${TARGETS[@]:0:$CI_TARGET_LIMIT}")
fi

if (( ${#TARGETS[@]} == 0 )); then
    echo "error: no fuzz targets to build" >&2
    exit 1
fi

echo "Building fuzz targets: ${TARGETS[*]}"

for FUZZER_TARGET in "${TARGETS[@]}"
do
    ninja -j "$NUM_JOBS" "$FUZZER_TARGET"
done

# SQL files from the public test suite seed the parser fuzzers.
SQL_CORPUS_TARGETS=" lexer_fuzzer select_parser_fuzzer create_parser_fuzzer "
CORPUS_DIR="$CH_BUILD/oss_fuzz_corpus"
rm -rf "$CORPUS_DIR"

for FUZZER_TARGET in "${TARGETS[@]}"
do
    # Find this binary in build directory and strip it
    mapfile -t BINARIES < <(find "$CH_BUILD" -type f -name "$FUZZER_TARGET")
    if (( ${#BINARIES[@]} != 1 )); then
        echo "error: expected exactly one $FUZZER_TARGET binary, found ${#BINARIES[@]}: ${BINARIES[*]-}" >&2
        exit 1
    fi
    # We have to preserve certain symbols e.g. LLVMFuzzerTestOneInput and some sanitizer-related once to not fail build checks:
    # https://github.com/google/oss-fuzz/blob/860447a7121e344cc1627f492f67f3a23e86e6c5/infra/base-images/base-runner/bad_build_check#L173
    # https://github.com/google/oss-fuzz/blob/860447a7121e344cc1627f492f67f3a23e86e6c5/infra/base-images/base-runner/test_all.py#L92-L96
    # because of that we strip only debug symbols
    strip --strip-debug "${BINARIES[0]}"
    cp -v "${BINARIES[0]}" "$OUT/"

    # copy out fuzzer options and the dictionaries they reference
    OPTIONS="$CH_SRC/tests/fuzz/$FUZZER_TARGET.options"
    if [ -f "$OPTIONS" ]; then
        cp "$OPTIONS" "$OUT/"
        while IFS= read -r DICT; do
            if [ -f "$CH_SRC/tests/fuzz/$DICT" ]; then
                cp "$CH_SRC/tests/fuzz/$DICT" "$OUT/"
            elif [ -f "$CH_SRC/tests/fuzz/dictionaries/$DICT" ]; then
                cp "$CH_SRC/tests/fuzz/dictionaries/$DICT" "$OUT/"
            else
                echo "error: $FUZZER_TARGET.options references dictionary '$DICT', found in neither tests/fuzz nor tests/fuzz/dictionaries" >&2
                exit 1
            fi
        done < <(sed -n 's/^[[:space:]]*dict[[:space:]]*=[[:space:]]*\([^[:space:]#]*\).*$/\1/p' "$OPTIONS")
    fi

    # prepare the seed corpus: committed seeds first, then public SQL tests
    CORPUS="$CORPUS_DIR/$FUZZER_TARGET"
    mkdir -p "$CORPUS"
    if [ -d "$CH_SRC/tests/fuzz/$FUZZER_TARGET.in" ]; then
        cp -r "$CH_SRC/tests/fuzz/$FUZZER_TARGET.in/." "$CORPUS/"
    fi
    if [[ "$SQL_CORPUS_TARGETS" == *" $FUZZER_TARGET "* ]]; then
        cp "$CH_SRC"/tests/queries/0_stateless/*.sql "$CORPUS/"
    fi
    if [ -n "$(find "$CORPUS" -type f -print -quit)" ]; then
        rm -f "$OUT/${FUZZER_TARGET}_seed_corpus.zip"
        zip -qrj "$OUT/${FUZZER_TARGET}_seed_corpus.zip" "$CORPUS"
    fi
done

# Coverage filenames are remapped from the source tree to the build tree. Stage
# exactly the files recorded in the packaged binaries at those mapped paths;
# generated files are already present in the build tree.
if [ "$SANITIZER" = "coverage" ]; then
    python3 - "$CH_SRC" "$CH_BUILD" "$OUT" "${TARGETS[@]}" <<'PY'
import json
from pathlib import Path
import shutil
import subprocess
import sys

source_root = Path(sys.argv[1])
build_root = Path(sys.argv[2])
output_root = Path(sys.argv[3])
mapped_files = set()

for target in sys.argv[4:]:
    result = subprocess.run(
        [
            "llvm-cov", "export", "--empty-profile", "--summary-only",
            str(output_root / target),
        ],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    report = json.loads(result.stdout)
    for datum in report["data"]:
        mapped_files.update(Path(entry["filename"])
                            for entry in datum["files"])

copied = 0
for mapped_file in sorted(mapped_files):
    try:
        relative = mapped_file.relative_to(build_root)
    except ValueError:
        raise SystemExit(
            f"error: coverage source {mapped_file} is outside {build_root}")

    if ".." in relative.parts:
        raise SystemExit(f"error: invalid coverage source path {mapped_file}")

    destination = build_root / relative
    source = source_root / relative
    if source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        copied += 1
    elif not destination.is_file():
        raise SystemExit(
            f"error: coverage source {mapped_file} is absent from both "
            f"{build_root} and {source_root}")

print(f"Staged {copied} source files for coverage")
PY
fi

# Just check binaries size
for FUZZER_TARGET in "${TARGETS[@]}"; do
    du -sh "$OUT/$FUZZER_TARGET"
done
