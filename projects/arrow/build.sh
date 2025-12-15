#!/bin/bash -eux
# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# 1. Build instrumented OpenSSL

OPENSSL_VERSION=3.5.4

cd ${SRC}
wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz
tar -xf openssl-${OPENSSL_VERSION}.tar.gz
cd openssl-${OPENSSL_VERSION}
# Assembler snippets would not be instrumented, disable them
./Configure no-apps no-docs no-tests no-shared no-asm
make -j
make install

# 2. Build Arrow C++ proper

ARROW=${SRC}/arrow/cpp

BUILD_DIR=${SRC}/build-dir
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

cmake ${ARROW} -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DARROW_DEPENDENCY_SOURCE=BUNDLED \
    -DARROW_OPENSSL_USE_SHARED=off \
    -DBOOST_SOURCE=SYSTEM \
    -DARROW_BOOST_USE_SHARED=off \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DARROW_EXTRA_ERROR_CONTEXT=off \
    \
    -DARROW_BUILD_SHARED=off \
    -DARROW_BUILD_STATIC=on \
    -DARROW_BUILD_BENCHMARKS=off \
    -DARROW_BUILD_EXAMPLES=off \
    -DARROW_BUILD_INTEGRATION=off \
    -DARROW_BUILD_TESTS=on \
    -DARROW_BUILD_UTILITIES=off \
    -DARROW_TEST_LINKAGE=static \
    -DPARQUET_BUILD_EXAMPLES=off \
    -DPARQUET_BUILD_EXECUTABLES=off \
    -DPARQUET_REQUIRE_ENCRYPTION=on \
    \
    -DARROW_CSV=on \
    -DARROW_JEMALLOC=off \
    -DARROW_MIMALLOC=off \
    -DARROW_PARQUET=on \
    -DARROW_WITH_BROTLI=on \
    -DARROW_WITH_BZ2=off \
    -DARROW_WITH_LZ4=on \
    -DARROW_WITH_SNAPPY=on \
    -DARROW_WITH_ZLIB=on \
    -DARROW_WITH_ZSTD=on \
    \
    -DARROW_USE_ASAN=off \
    -DARROW_USE_UBSAN=off \
    -DARROW_USE_TSAN=off \
    -DARROW_FUZZING=on \

cmake --build . -j$(nproc)

${ARROW}/build-support/fuzzing/generate_corpuses.sh ${BUILD_DIR}/release

# Copy fuzz targets
find . -executable -name "*-fuzz" -exec cp -a -v '{}' ${OUT} \;
# Copy seed corpuses
find . -name "*-fuzz_seed_corpus.zip" -exec cp -a -v '{}' ${OUT} \;
