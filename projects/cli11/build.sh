#!/bin/bash -eu
set -o pipefail
for f in "$SRC"/fuzzers/*.cc; do
  b="$(basename "$f" .cc)"
  "$CXX" ${CXXFLAGS:-} -std=c++17 -I"$SRC/cli11/include" \
    "$f" -o "$OUT/$b" $LIB_FUZZING_ENGINE ${LDFLAGS:-}
done
# Package seed corpus if present.
[ -d "$SRC/fuzzers/corpus" ] && zip -rq "$OUT/fuzz_cli_parse_seed_corpus.zip" "$SRC/fuzzers/corpus" || true
