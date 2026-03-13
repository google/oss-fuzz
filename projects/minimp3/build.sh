#!/bin/bash -eu

# minimp3 is header-only, no library build needed.
# Fuzz targets include minimp3.h/minimp3_ex.h with MINIMP3_IMPLEMENTATION.

TARGETS="fuzz_decode_frame fuzz_decode_buf fuzz_decode_ex"

for target in $TARGETS; do
    $CC $CFLAGS -I$SRC/minimp3 -c $SRC/${target}.c -o $WORK/${target}.o
    $CXX $CXXFLAGS $WORK/${target}.o -o $OUT/${target} $LIB_FUZZING_ENGINE -lm
done

# Dictionary (shared by all targets)
for target in $TARGETS; do
    cp $SRC/mp3.dict $OUT/${target}.dict
done

# Seed corpus: grab test vectors from upstream if available
if [ -d "$SRC/minimp3/vectors" ]; then
    for target in $TARGETS; do
        mkdir -p $WORK/${target}_corpus
        find $SRC/minimp3/vectors -name "*.bit" -o -name "*.mp3" | head -20 | \
            while read f; do cp "$f" $WORK/${target}_corpus/; done
        cd $WORK && zip -j $OUT/${target}_seed_corpus.zip ${target}_corpus/* || true
    done
fi
