#!/bin/sh

# build and install cgif
meson setup -Dfuzzer=true --prefix=$WORK --libdir=lib --default-library=static build
meson install -C build
# run tests:
# This is going to generate the seed corpus from all the tests
meson test -C build

cp "build/fuzz/cgif_fuzzer_seed_corpus.zip" $OUT/.

# build cgif's fuzz target
$CC $CFLAGS -o "$OUT/cgif_fuzzer" -I"$WORK/include" \
  fuzz/cgif_fuzzer.c "$WORK/lib/libcgif.a" $LIB_FUZZING_ENGINE
