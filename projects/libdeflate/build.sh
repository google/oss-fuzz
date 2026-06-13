#!/bin/bash -eu

# Build libdeflate
cmake . -DCMAKE_BUILD_TYPE=Release \
        -DLIBDEFLATE_BUILD_STATIC_LIB=ON \
        -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
        -DLIBDEFLATE_BUILD_GZIP=OFF \
        -DCMAKE_C_FLAGS="$CFLAGS" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS"
make -j$(nproc) deflate_static

# Build deflate_decompress fuzzer (uses guarded allocations for buffer OOB detection)
$CC $CFLAGS -Iinclude -c $SRC/deflate_decompress_fuzzer.c -o deflate_decompress_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE deflate_decompress_fuzzer.o \
    libdeflate.a -o $OUT/deflate_decompress_fuzzer

# Build gzip_decompress fuzzer
$CC $CFLAGS -Iinclude -c $SRC/gzip_decompress_fuzzer.c -o gzip_decompress_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE gzip_decompress_fuzzer.o \
    libdeflate.a -o $OUT/gzip_decompress_fuzzer

# Build zlib_decompress fuzzer
$CC $CFLAGS -Iinclude -c $SRC/zlib_decompress_fuzzer.c -o zlib_decompress_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE zlib_decompress_fuzzer.o \
    libdeflate.a -o $OUT/zlib_decompress_fuzzer

# Build deflate_compress fuzzer (round-trip: compress then decompress)
$CC $CFLAGS -Iinclude -c $SRC/deflate_compress_fuzzer.c -o deflate_compress_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE deflate_compress_fuzzer.o \
    libdeflate.a -o $OUT/deflate_compress_fuzzer

# Build adler32/crc32 checksum fuzzers
$CC $CFLAGS -Iinclude -c $SRC/checksum_fuzzer.c -o checksum_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE checksum_fuzzer.o \
    libdeflate.a -o $OUT/checksum_fuzzer

# Seed corpora: real DEFLATE/gzip compressed files make great seeds
zip $OUT/deflate_decompress_fuzzer_seed_corpus.zip \
    $(find $SRC/libdeflate -name "*.gz" 2>/dev/null | head -20) 2>/dev/null || true
cp $OUT/deflate_decompress_fuzzer_seed_corpus.zip $OUT/gzip_decompress_fuzzer_seed_corpus.zip 2>/dev/null || true
