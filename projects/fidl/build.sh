#!/bin/bash -e

JIRI_HOME=`pwd`/.jiri_root/bin
$JIRI_HOME/jiri import fidl https://fuchsia.googlesource.com/manifest
$JIRI_HOME/jiri update
./scripts/build-magenta.sh
./packages/gn/gen.py -m fidl --ignore-skia --args=enable_ossfuzz=true
./buildtools/ninja -C out/debug-x86-64

cp out/debug-x86-64/host_x64/fidl-fuzzer $OUT/fidl-fuzzer
cp -r lib/fidl/fuzz/input_corpus/ $OUT/input_corpus
cp -r magenta/system/host/fidl/examples/ $OUT/examples
