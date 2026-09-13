#!/bin/bash -eu
# lexindex: nine libFuzzer targets over the safe blob parsers, seeded with the golden blobs the
# crate's own tests check. Link-time optimisation must stay off: under LTO the library is re-codegen'd
# from bitcode that does not carry the coverage instrumentation, and the fuzzer explores nothing
# while reporting no crashes (measured upstream: 2 599 instrumented edges -> 331). The fuzz manifest
# says so; the env override is what outranks any cargo config on the builder.
cd "$SRC/lexindex/fuzz"
export CARGO_PROFILE_RELEASE_LTO=false
cargo fuzz build -O --debug-assertions

for target in parse_compact parse_closed parse_dict parse_perfect parse_overlay \
              parse_overlay_untrusted parse_string parse_mphf parse_inspect; do
  cp "target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
  # Every target reads a header of one of the formats the golden blobs are written in; reaching a
  # valid header by mutation alone is hopeless, so all of them start from the same seeds.
  zip -q -j "$OUT/${target}_seed_corpus.zip" "$SRC"/lexindex/tests/data/*
done
