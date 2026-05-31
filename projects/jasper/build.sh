#!/bin/bash -eu

# Build JasPer library
cd $SRC/jasper
mkdir -p build && cd build
cmake .. \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$CFLAGS" \
    -DJAS_ENABLE_SHARED=false \
    -DJAS_ENABLE_DOC=false \
    -DJAS_ENABLE_PROGRAMS=false \
    -DJAS_ENABLE_AUTOMATIC_DEPENDENCIES=false \
    -DCMAKE_BUILD_TYPE=Release
make -j$(nproc) jasper

LIB=$SRC/jasper/build/src/libjasper/libjasper.a
INC=$SRC/jasper/src/libjasper/include

# Build decode fuzzer
$CC $CFLAGS -I$INC -I$SRC/jasper/build/src/libjasper/include \
    $SRC/jasper_decode_fuzzer.c \
    $LIB $LIB_FUZZING_ENGINE \
    -lm -o $OUT/jasper_decode_fuzzer

# Build encode fuzzer
$CC $CFLAGS -I$INC -I$SRC/jasper/build/src/libjasper/include \
    $SRC/jasper_encode_fuzzer.c \
    $LIB $LIB_FUZZING_ENGINE \
    -lm -o $OUT/jasper_encode_fuzzer

# Build transcode fuzzer
$CC $CFLAGS -I$INC -I$SRC/jasper/build/src/libjasper/include \
    $SRC/jasper_transcode_fuzzer.c \
    $LIB $LIB_FUZZING_ENGINE \
    -lm -o $OUT/jasper_transcode_fuzzer

# Copy seed corpus from jasper test suite
find $SRC/jasper/data -name "*.jp2" -o -name "*.jpc" -o -name "*.pgx" \
    -o -name "*.bmp" -o -name "*.ras" 2>/dev/null | \
    while read f; do cp "$f" $OUT/; done

zip -j $OUT/jasper_decode_fuzzer_seed_corpus.zip \
    $SRC/jasper/data/images/*.jp2 \
    $SRC/jasper/data/images/*.jpc \
    $SRC/jasper/data/images/*.bmp 2>/dev/null || true

cp $OUT/jasper_decode_fuzzer_seed_corpus.zip \
   $OUT/jasper_encode_fuzzer_seed_corpus.zip 2>/dev/null || true
cp $OUT/jasper_decode_fuzzer_seed_corpus.zip \
   $OUT/jasper_transcode_fuzzer_seed_corpus.zip 2>/dev/null || true
