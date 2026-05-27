#!/bin/bash -eu
#
# OSS-Fuzz build script for libpng.
#
# Environment variables injected by OSS-Fuzz:
#   $CC, $CXX           – compiler (clang / clang++)
#   $CFLAGS, $CXXFLAGS  – sanitizer + coverage flags
#   $LIB_FUZZING_ENGINE – fuzzing engine link flag (-fsanitize=fuzzer etc.)
#   $OUT                – output directory for fuzzer binaries
#   $SRC                – source root (set in Dockerfile)

# ---------------------------------------------------------------------------
# 1. Build zlib (static)
# ---------------------------------------------------------------------------
echo "==> Building zlib"
cd "$SRC/zlib"
# Use the configure wrapper so we get a plain static archive.
CFLAGS="$CFLAGS" ./configure \
    --prefix="$WORK" \
    --static
make -j"$(nproc)" clean
make -j"$(nproc)"
make install

# ---------------------------------------------------------------------------
# 2. Build libpng (static, cmake)
# ---------------------------------------------------------------------------
echo "==> Building libpng"
mkdir -p "$WORK/libpng-build"
cd "$WORK/libpng-build"

cmake "$SRC/libpng" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_INSTALL_PREFIX="$WORK" \
    -DPNG_SHARED=OFF \
    -DPNG_STATIC=ON \
    -DPNG_TESTS=OFF \
    -DZLIB_ROOT="$WORK" \
    -DZLIB_LIBRARY="$WORK/lib/libz.a" \
    -DZLIB_INCLUDE_DIR="$WORK/include"

make -j"$(nproc)"
make install

# ---------------------------------------------------------------------------
# 3. Compile fuzzer binaries
# ---------------------------------------------------------------------------
echo "==> Compiling fuzzers"

INCLUDES="-I$WORK/include"
LIBS="$WORK/lib/libpng.a $WORK/lib/libz.a"

# png_read_fuzzer
$CXX $CXXFLAGS $INCLUDES \
    "$SRC/png_read_fuzzer.cc" \
    $LIB_FUZZING_ENGINE \
    $LIBS \
    -o "$OUT/png_read_fuzzer"

# png_write_fuzzer
$CXX $CXXFLAGS $INCLUDES \
    "$SRC/png_write_fuzzer.cc" \
    $LIB_FUZZING_ENGINE \
    $LIBS \
    -o "$OUT/png_write_fuzzer"

echo "==> Build complete. Fuzzers written to $OUT/"
ls -lh "$OUT/"
