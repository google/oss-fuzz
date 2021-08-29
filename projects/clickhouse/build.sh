#!/bin/bash -eu
# Copyright 2021 Google LLC
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

mkdir $SRC/ClickHouse/build
cd $SRC/ClickHouse/build

sed -i -e '/warnings.cmake)/d' $SRC/ClickHouse/CMakeLists.txt

# It will be hard to maintain any compilation fails (if any) in two repositories.
# Also ClickHouse won't compile without this.
# It is very strange, because we have as many warnings as you could imagine.
sed -i -e 's/add_warning(/no_warning(/g' $SRC/ClickHouse/CMakeLists.txt

# ClickHouse uses libcxx from contrib.
# Enabling this manually will cause duplicate symbols at linker stage.
CXXFLAGS=${CXXFLAGS//-stdlib=libc++/}

CLICKHOUSE_CMAKE_FLAGS=(
    "-DCMAKE_CXX_COMPILER_LAUNCHER=/usr/bin/ccache"
    "-DCMAKE_C_COMPILER=$CC"
    "-DCMAKE_CXX_COMPILER=$CXX"
    "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
    "-DLIB_FUZZING_ENGINE:STRING=$LIB_FUZZING_ENGINE"
    "-DENABLE_EMBEDDED_COMPILER=0"
    "-DENABLE_THINLTO=0"
    "-DENABLE_TESTS=0"
    "-DENABLE_EXAMPLES=0"
    "-DENABLE_UTILS=0"
    "-DENABLE_JEMALLOC=0"
    "-DENABLE_FUZZING=1"
    "-DENABLE_CLICKHOUSE_ODBC_BRIDGE=OFF"
    "-DENABLE_LIBRARIES=0"
    "-DENABLE_SSL=1"
    "-DUSE_INTERNAL_SSL_LIBRARY=1"
    "-DUSE_UNWIND=ON"
)

if [ "$SANITIZER" = "coverage" ]; then
    cmake  -G Ninja $SRC/ClickHouse ${CLICKHOUSE_CMAKE_FLAGS[@]} -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS"
elif [ "$SANITIZER" = "undefined" ]; then
    cmake  -G Ninja $SRC/ClickHouse ${CLICKHOUSE_CMAKE_FLAGS[@]} -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" -DSANITIZE=$SANITIZER
else
    cmake  -G Ninja $SRC/ClickHouse ${CLICKHOUSE_CMAKE_FLAGS[@]} -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" -DWITH_COVERAGE=1 -DSANITIZE=$SANITIZER
fi

NUM_JOBS=$(($(nproc || grep -c ^processor /proc/cpuinfo) / 2))

TARGETS=$(find $SRC/ClickHouse/src -name '*_fuzzer.cpp' -execdir basename {} .cpp ';' | tr '\n' ' ')

for FUZZER_TARGET in $TARGETS
do
    ninja -j $NUM_JOBS $FUZZER_TARGET
    # Find this binary in build directory and strip it
    TEMP=$(find $SRC/ClickHouse/build -name $FUZZER_TARGET)
    strip --strip-unneeded $TEMP
done

# copy out fuzzer binaries
find $SRC/ClickHouse/build -name '*_fuzzer' -exec cp -v '{}' $OUT ';'

# copy out fuzzer options and dictionaries
cp $SRC/ClickHouse/tests/fuzz/*.dict $OUT/
cp $SRC/ClickHouse/tests/fuzz/*.options $OUT/

# prepare corpus dirs
mkdir $SRC/ClickHouse/tests/fuzz/lexer_fuzzer.in/
mkdir $SRC/ClickHouse/tests/fuzz/select_parser_fuzzer.in/
mkdir $SRC/ClickHouse/tests/fuzz/create_parser_fuzzer.in/

# prepare corpus
cp $SRC/ClickHouse/tests/queries/0_stateless/*.sql $SRC/ClickHouse/tests/fuzz/lexer_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/0_stateless/*.sql $SRC/ClickHouse/tests/fuzz/select_parser_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/0_stateless/*.sql $SRC/ClickHouse/tests/fuzz/create_parser_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/1_stateful/*.sql $SRC/ClickHouse/tests/fuzz/lexer_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/1_stateful/*.sql $SRC/ClickHouse/tests/fuzz/select_parser_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/1_stateful/*.sql $SRC/ClickHouse/tests/fuzz/create_parser_fuzzer.in/

# copy out corpus
cd $SRC/ClickHouse/tests/fuzz
for dir in *_fuzzer.in; do
    fuzzer=$(basename $dir .in)
    zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "${dir}/"
done

# copy sources for code coverage if required
if [ "$SANITIZER" = "coverage" ]; then
    mkdir -p $OUT/src/ClickHouse/
    cp -rL --parents $SRC/ClickHouse/src $OUT
    cp -rL --parents $SRC/ClickHouse/base $OUT
    cp -rL --parents $SRC/ClickHouse/programs $OUT
fi

# Just check binaries size
BINARIES_SIZE=$(find $SRC/ClickHouse/build -name '*_fuzzer' -exec du -sh '{}' ';')
