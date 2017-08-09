#!/bin/bash -e

JIRI_HOME=`pwd`/.jiri_root/bin
$JIRI_HOME/jiri import fidl https://fuchsia.googlesource.com/manifest
$JIRI_HOME/jiri update
./scripts/build-magenta.sh
./packages/gn/gen.py -m fidl --ignore-skia --args=enable_ossfuzz=true
./buildtools/ninja -C out/debug-x86-64

cp out/debug-x86-64/host_x64/fidl-fuzzer $OUT/fuchsia_fidl_fuzzer
zip -j $OUT/fuchsia_fidl_seed_corpus.zip lib/fidl/fuzz/input_corpus/* magenta/system/host/fidl/examples/*
