#!/bin/bash -eu
# OSS-Fuzz build script for the GayHydra decompiler harnesses.
# See docs/security/OSS_FUZZ.md.

CPP_DIR="$SRC/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
FUZZ_DIR="$CPP_DIR/fuzz"

cd "$CPP_DIR"

# Build decompiler object files with the OSS-Fuzz sanitizers.
# The decompiler's existing Makefile produces objects in-place; we
# don't link the main binary, only the .o files our harnesses need.
make OPT_CXXFLAGS="$CXXFLAGS" \
     OPT_LDFLAGS="" \
     bare_libdecomp.a 2>/dev/null || \
make OPT_CXXFLAGS="$CXXFLAGS" \
     OPT_LDFLAGS="" \
     xml.o marshal.o address.o space.o

cd "$FUZZ_DIR"

for harness in fuzz_xml fuzz_marshal; do
    $CXX $CXXFLAGS -std=c++11 -I"$CPP_DIR" -c "$harness.cc" -o "$harness.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE "$harness.o" \
        "$CPP_DIR"/xml.o "$CPP_DIR"/marshal.o \
        "$CPP_DIR"/address.o "$CPP_DIR"/space.o \
        -o "$OUT/$harness"

    # Copy seed corpus if it exists.
    if [ -d "$FUZZ_DIR/seeds/$harness" ]; then
        ( cd "$FUZZ_DIR/seeds/$harness" && \
          zip -r "$OUT/${harness}_seed_corpus.zip" . )
    fi
done
