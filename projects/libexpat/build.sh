#!/bin/bash -eu

cd "$SRC/libexpat/expat"
cmake . \
    -DCMAKE_BUILD_TYPE=Release \
    -DEXPAT_BUILD_DOCS=OFF \
    -DEXPAT_BUILD_EXAMPLES=OFF \
    -DEXPAT_BUILD_TESTS=OFF \
    -DEXPAT_BUILD_TOOLS=OFF \
    -DEXPAT_SHARED_LIBS=OFF \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS"
make -j$(nproc)

# Build the parse fuzzer
$CC $CFLAGS -I./lib \
    -c fuzz/xml_parse_fuzzer.c \
    -o xml_parse_fuzzer.o

$CC $CFLAGS $LIB_FUZZING_ENGINE \
    xml_parse_fuzzer.o \
    ./libexpat.a \
    -o "$OUT/xml_parse_fuzzer"

# Build the parsebuffer fuzzer
$CC $CFLAGS -I./lib \
    -c fuzz/xml_parsebuffer_fuzzer.c \
    -o xml_parsebuffer_fuzzer.o

$CC $CFLAGS $LIB_FUZZING_ENGINE \
    xml_parsebuffer_fuzzer.o \
    ./libexpat.a \
    -o "$OUT/xml_parsebuffer_fuzzer"

# Seed corpus: use existing XML test cases
find "$SRC/libexpat/expat/tests" -name "*.xml" 2>/dev/null | head -50 | \
    xargs -I{} cp {} "$OUT/xml_parse_fuzzer_seed_corpus/" 2>/dev/null || true
mkdir -p "$OUT/xml_parse_fuzzer_seed_corpus"
echo "<root/>" > "$OUT/xml_parse_fuzzer_seed_corpus/minimal.xml"
echo "<?xml version='1.0'?><root attr='val'>text</root>" > "$OUT/xml_parse_fuzzer_seed_corpus/attrs.xml"
zip -j "$OUT/xml_parse_fuzzer_seed_corpus.zip" "$OUT/xml_parse_fuzzer_seed_corpus/"*
cp "$OUT/xml_parse_fuzzer_seed_corpus.zip" "$OUT/xml_parsebuffer_fuzzer_seed_corpus.zip"
