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


mkdir -p $SRC/ClickHouse/build && cd $SRC/ClickHouse/build

[ -e CMakeLists ] && rm -rf CMakeFiles
[ -e CMakeCache.txt ] && rm -rf CMakeCache.txt

sed -i -e '/warnings.cmake)/d' $SRC/ClickHouse/CMakeLists.txt

# It will be hard to maintain any compilation fails (if any) in two repositories.
# Also ClickHouse won't compile without this.
# It is very strange, because we have as many warnings as you could imagine.
sed -i -e 's/add_warning(/no_warning(/g' $SRC/ClickHouse/CMakeLists.txt

# ClickHouse uses libcxx from contrib.
# Enabling libstdc++ manually will cause duplicate symbols at linker stage.
# Plus we want to fuzz the same binary as we have in our CI
# https://github.com/ClickHouse/ClickHouse/blob/2e2ef087129ed072404bdc084e8028a5c5869dc0/PreLoad.cmake#L23
unset CFLAGS
unset CXXFLAGS
unset LDFLAGS

# ClickHouse builds `protoc` from sources to be dependent only on compiler
# but if we build ClickHouse with any kind of sanitizer, then `protoc`
# will be built with sanitizer too...
# Protoc will be used during ClickHouse builds to generate .cpp sources from .proto files
# and everything works in our CI, but not here...
# We use libprotobuf-mutator and self-written script to generate SQL-based AST from mutated .proto
# Maybe some of proto files are too complex and this is the cause of `protoc` failures
# So, this flag only helps to supress error from `protoc` built with any kind of sanitizer
export MSAN_OPTIONS=exit_code=0

printenv

NUM_JOBS=$(nproc || grep -c ^processor /proc/cpuinfo)

if (( $NUM_JOBS > 10 )); then
    NUM_JOBS=$(expr $NUM_JOBS / 2)
fi

CLICKHOUSE_CMAKE_FLAGS=(
    "-DCMAKE_CXX_COMPILER_LAUNCHER=/usr/bin/ccache"
    "-DCMAKE_C_COMPILER=$CC"
    "-DCMAKE_CXX_COMPILER=$CXX"
    "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
    "-DLIB_FUZZING_ENGINE:STRING=$LIB_FUZZING_ENGINE"
    "-DENABLE_FUZZING=1"
    "-DWITH_COVERAGE=1"
    "-DENABLE_PROTOBUF=1"
    "-DPARALLEL_COMPILE_JOBS=$NUM_JOBS"
)

if [ "$SANITIZER" = "coverage" ]; then
    cmake  -G Ninja $SRC/ClickHouse ${CLICKHOUSE_CMAKE_FLAGS[@]} -DWITH_COVERAGE=1
else
    cmake  -G Ninja $SRC/ClickHouse ${CLICKHOUSE_CMAKE_FLAGS[@]} -DWITH_COVERAGE=1 -DSANITIZE=$SANITIZER
fi

TARGETS=$(find $SRC/ClickHouse/src $SRC/ClickHouse/programs -name '*_fuzzer.cpp' -execdir basename {} .cpp ';' | tr '\n' ' ')

for FUZZER_TARGET in $TARGETS
do
    # Skip this fuzzer because of linker errors (the size of the binary is too big)
    if [ "$FUZZER_TARGET" = "execute_query_fuzzer" ]; then
        continue
    fi
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
mkdir -p $SRC/ClickHouse/tests/fuzz/lexer_fuzzer.in/
mkdir -p $SRC/ClickHouse/tests/fuzz/select_parser_fuzzer.in/
mkdir -p $SRC/ClickHouse/tests/fuzz/create_parser_fuzzer.in/
mkdir -p $SRC/ClickHouse/tests/fuzz/execute_query_fuzzer.in/

# prepare corpus
cp $SRC/ClickHouse/tests/queries/0_stateless/*.sql $SRC/ClickHouse/tests/fuzz/lexer_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/0_stateless/*.sql $SRC/ClickHouse/tests/fuzz/select_parser_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/0_stateless/*.sql $SRC/ClickHouse/tests/fuzz/create_parser_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/0_stateless/*.sql $SRC/ClickHouse/tests/fuzz/execute_query_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/1_stateful/*.sql $SRC/ClickHouse/tests/fuzz/lexer_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/1_stateful/*.sql $SRC/ClickHouse/tests/fuzz/select_parser_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/1_stateful/*.sql $SRC/ClickHouse/tests/fuzz/create_parser_fuzzer.in/
cp $SRC/ClickHouse/tests/queries/1_stateful/*.sql $SRC/ClickHouse/tests/fuzz/execute_query_fuzzer.in/

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
fi

# Just check binaries size
BINARIES_SIZE=$(find $SRC/ClickHouse/build -name '*_fuzzer' -exec du -sh '{}' ';')
