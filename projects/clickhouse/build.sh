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

# This files contain some errors.
# It wasn't build in our CI. So, it will be removed soon from upstream.
# P.S. Sorry for my Bash skills.
sed -i -e '$d' $SRC/ClickHouse/src/Common/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Common/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Common/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Common/examples/CMakeLists.txt
rm -rf $SRC/ClickHouse/src/Common/examples/YAML_fuzzer.cpp

sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt
sed -i -e '$d' $SRC/ClickHouse/src/Parsers/examples/CMakeLists.txt

rm -rf $SRC/ClickHouse/src/Parsers/examples/lexer_fuzzer.cpp
rm -rf $SRC/ClickHouse/src/Parsers/examples/create_parser_fuzzer.cpp
rm -rf $SRC/ClickHouse/src/Parsers/examples/select_parser_fuzzer.cpp


# Turn off all libraries, but turn on only necessary
cmake -G Ninja $SRC/ClickHouse \
        -DCMAKE_CXX_COMPILER_LAUNCHER=/usr/bin/ccache \
        -DCMAKE_C_COMPILER=$CC \
        -DCMAKE_CXX_COMPILER=$CXX \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DSANITIZE=$SANITIZER \
        -DENABLE_THINLTO=0  \
        -DENABLE_TESTS=0 \
        -DENABLE_EXAMPLES=1 \
        -DENABLE_UTILS=0 \
        -DENABLE_JEMALLOC=0 \
        -DENABLE_FUZZING=1 \
        -DLIB_FUZZING_ENGINE:STRING="$LIB_FUZZING_ENGINE" \
        -DENABLE_EMBEDDED_COMPILER=0 \
        -DENABLE_CLICKHOUSE_ODBC_BRIDGE=OFF \
        -DENABLE_LIBRARIES=0 \
        -DUSE_YAML_CPP=1

NUM_JOBS=$(($(nproc || grep -c ^processor /proc/cpuinfo)))

ninja -j $NUM_JOBS

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
    cp -rL --parents $SRC/ClickHouse/contrib $OUT
fi
