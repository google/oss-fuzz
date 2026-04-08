#!/bin/bash
# Local build test script for OSS-Fuzz integration
# This script helps test the fuzzer build without the full OSS-Fuzz infrastructure

set -e

echo "=== Testing OSS-Fuzz build locally ==="

# Check if clang is available
if ! command -v clang &> /dev/null; then
    echo "Error: clang is required but not found"
    echo "Install with: sudo apt-get install clang"
    exit 1
fi

# Check if clang++ is available
if ! command -v clang++ &> /dev/null; then
    echo "Error: clang++ is required but not found"
    echo "Install with: sudo apt-get install clang"
    exit 1
fi

# Set up environment variables similar to OSS-Fuzz
export CC=clang
export CXX=clang++
export CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,fuzzer-no-link"
export CXXFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,fuzzer-no-link"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
export OUT="${OUT:-$(pwd)/out}"

echo "Build output directory: $OUT"
mkdir -p "$OUT"

# Get the repository root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "Repository root: $REPO_ROOT"

cd "$REPO_ROOT"

# Create build directory
BUILD_DIR="$REPO_ROOT/build-fuzz"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo ""
echo "=== Configuring with CMake ==="
cmake .. \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DENABLE_ONLINE_TESTS=OFF \
    -DENABLE_STATIC=ON

echo ""
echo "=== Building libmongocrypt ==="
make -j$(nproc) mongocrypt_static

echo ""
echo "=== Building fuzz_kms ==="
$CC $CFLAGS -c ../test/fuzz_kms.c \
    -I../kms-message/src \
    -I../src \
    -o fuzz_kms.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_kms.o \
    -o "$OUT/fuzz_kms" \
    libmongocrypt_static.a \
    kms-message/libkms_message_static.a \
    -Wl,--start-group \
    _mongo-c-driver/src/libbson/libbson-static-for-libmongocrypt.a \
    -Wl,--end-group

echo ""
echo "=== Building fuzz_mongocrypt ==="
$CC $CFLAGS -c ../test/fuzz_mongocrypt.c \
    -I../src \
    -I. \
    -o fuzz_mongocrypt.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_mongocrypt.o \
    -o "$OUT/fuzz_mongocrypt" \
    libmongocrypt_static.a \
    kms-message/libkms_message_static.a \
    -Wl,--start-group \
    _mongo-c-driver/src/libbson/libbson-static-for-libmongocrypt.a \
    -Wl,--end-group

echo ""
echo "=== Build successful! ==="
echo ""
echo "Fuzzers built:"
ls -lh "$OUT"/fuzz_*

echo ""
echo "To run a fuzzer:"
echo "  $OUT/fuzz_kms -max_total_time=60"
echo "  $OUT/fuzz_mongocrypt -max_total_time=60"
echo ""
echo "To run with a corpus directory:"
echo "  mkdir -p corpus"
echo "  $OUT/fuzz_kms corpus/ -max_total_time=60"

