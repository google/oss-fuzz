#!/bin/bash
# Phase 9.3: OSS-Fuzz build script for Dilithion
# This file should be placed in google/oss-fuzz/projects/dilithion/build.sh

set -eux

# Set compiler flags for fuzzing
export CC=clang
export CXX=clang++
export CFLAGS="$CFLAGS -DDILITHIUM_MODE=3"
export CXXFLAGS="$CXXFLAGS -std=c++17"

# Build RandomX (if not already built)
if [ ! -f /randomx/build/librandomx.a ]; then
    cd /randomx
    mkdir -p build && cd build
    cmake .. -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS"
    make -j$(nproc)
fi

# Build Dilithium (if not already built)
if [ ! -f /dilithium/ref/libpqcrystals_dilithium3_ref.a ]; then
    cd /dilithium/ref
    make clean
    CC=clang CFLAGS="$CFLAGS -DDILITHIUM_MODE=3" make -j$(nproc)
fi

# Build Dilithion fuzz targets
cd /src/dilithion

# Set environment variables
export RANDOMX_BUILD_DIR=/randomx/build
export DILITHIUM_DIR=/dilithium/ref

# Build fuzz targets
# OSS-Fuzz will look for binaries in $OUT directory
export OUT=$OUT

# Build individual fuzz targets
make fuzz_sha3
cp fuzz_sha3 $OUT/

make fuzz_transaction
cp fuzz_transaction $OUT/

make fuzz_block
cp fuzz_block $OUT/

make fuzz_serialize
cp fuzz_serialize $OUT/

make fuzz_mempool
cp fuzz_mempool $OUT/

make fuzz_rpc
cp fuzz_rpc $OUT/

make fuzz_p2p_validation
cp fuzz_p2p_validation $OUT/

echo "✅ All fuzz targets built successfully"
ls -lh $OUT/

