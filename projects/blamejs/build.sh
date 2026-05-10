#!/bin/bash -eu
#
# OSS-Fuzz build script for blamejs.
#
# Wires every fuzz/<name>.fuzz.js harness into a libFuzzer-shaped
# runnable via the base-builder-javascript image's
# compile_javascript_fuzzer helper. The matching
# fuzz/<name>_seed_corpus/ directory is zipped into the seed corpus
# the engine bootstraps from.

cd "$SRC/blamejs"

for fuzzer in fuzz/*.fuzz.js; do
  base=$(basename "$fuzzer" .fuzz.js)
  echo "[blamejs build] compiling $base"
  compile_javascript_fuzzer blamejs "$fuzzer" --sync

  seed_dir="fuzz/${base}_seed_corpus"
  if [ -d "$seed_dir" ]; then
    echo "[blamejs build] packaging seed corpus for $base"
    ( cd "$seed_dir" && zip -q -r "$OUT/${base}_seed_corpus.zip" . )
  fi
done

echo "[blamejs build] done — $(find "$OUT" -mindepth 1 -maxdepth 1 | wc -l) artifacts in \$OUT"
