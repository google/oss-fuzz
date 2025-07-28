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

ARROW=${SRC}/arrow/cpp

export BUILD_DIR=$SRC/build-dir
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}
#cd ${WORK}

# The CMake build setup compiles and runs the Thrift compiler, but ASAN
# would report leaks and error out.
export ASAN_OPTIONS="detect_leaks=0"

cmake ${ARROW} -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DARROW_DEPENDENCY_SOURCE=BUNDLED \
    -DBOOST_SOURCE=SYSTEM \
    -DBoost_USE_STATIC_RUNTIME=on \
    -DARROW_BOOST_USE_SHARED=off \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DARROW_EXTRA_ERROR_CONTEXT=off \
    -DARROW_JEMALLOC=off \
    -DARROW_MIMALLOC=off \
    -DARROW_FILESYSTEM=off \
    -DARROW_PARQUET=on \
    -DARROW_BUILD_SHARED=off \
    -DARROW_BUILD_STATIC=on \
    -DARROW_BUILD_TESTS=on \
    -DARROW_BUILD_INTEGRATION=off \
    -DARROW_BUILD_BENCHMARKS=off \
    -DARROW_BUILD_EXAMPLES=off \
    -DARROW_BUILD_UTILITIES=off \
    -DARROW_TEST_LINKAGE=static \
    -DPARQUET_BUILD_EXAMPLES=off \
    -DPARQUET_BUILD_EXECUTABLES=off \
    -DPARQUET_REQUIRE_ENCRYPTION=off \
    -DARROW_WITH_BROTLI=on \
    -DARROW_WITH_BZ2=off \
    -DARROW_WITH_LZ4=on \
    -DARROW_WITH_SNAPPY=on \
    -DARROW_WITH_ZLIB=on \
    -DARROW_WITH_ZSTD=on \
    -DARROW_USE_GLOG=off \
    -DARROW_USE_ASAN=off \
    -DARROW_USE_UBSAN=off \
    -DARROW_USE_TSAN=off \
    -DARROW_FUZZING=on \

cmake --build . -j$(nproc)

cp -a release/* ${OUT}

# Remove unit tests from out
rm $OUT/*-test

${ARROW}/build-support/fuzzing/generate_corpuses.sh ${OUT}
