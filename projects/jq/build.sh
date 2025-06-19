#!/bin/bash -eu
#
# Copyright 2023 Google LLC
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

git submodule init
git submodule update
autoreconf -fi
./configure --with-oniguruma=builtin
make -j$(nproc)

$CC $CFLAGS -c tests/jq_fuzz_parse.c \
    -I./src -o ./jq_fuzz_parse.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./jq_fuzz_parse.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o $OUT/jq_fuzz_parse -I./src

$CC $CFLAGS -c tests/jq_fuzz_compile.c \
    -I./src -o ./jq_fuzz_compile.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./jq_fuzz_compile.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o $OUT/jq_fuzz_compile -I./src

$CC $CFLAGS -c tests/jq_fuzz_load_file.c \
    -I./src -o ./jq_fuzz_load_file.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./jq_fuzz_load_file.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o $OUT/jq_fuzz_load_file -I./src

$CC $CFLAGS -c tests/jq_fuzz_parse_extended.c \
    -I./src -o ./jq_fuzz_parse_extended.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./jq_fuzz_parse_extended.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o $OUT/jq_fuzz_parse_extended -I./src

$CC $CFLAGS -c tests/jq_fuzz_parse_stream.c \
    -I./src -o ./jq_fuzz_parse_stream.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./jq_fuzz_parse_stream.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o $OUT/jq_fuzz_parse_stream -I./src

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./tests/jq_fuzz_execute.cpp \
    -I./src \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a\
    -o $OUT/jq_fuzz_execute -I./src

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./tests/jq_fuzz_fixed.cpp \
    -I./src \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o $OUT/jq_fuzz_fixed -I./src


# Build corpus
mkdir $SRC/seeds
find . -name "*.jq" -exec cp {} $SRC/seeds/ \;
zip -rj $OUT/jq_fuzz_execute_seed_corpus.zip $SRC/seeds/

# Copy dictionary
cp $SRC/jq.dict $OUT/jq_fuzz_execute.dict
