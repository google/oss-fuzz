#!/bin/bash -eux
#
# Copyright 2016 Google Inc.
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

mkdir $WORK/icu
cd $WORK/icu

# TODO: icu build failes without -DU_USE_STRTOD_L=0
DEFINES="-DU_CHARSET_IS_UTF8=1 -DU_USING_ICU_NAMESPACE=0 -DU_ENABLE_DYLOAD=0 -DU_USE_STRTOD_L=0"
CFLAGS="$CFLAGS $DEFINES"
CXXFLAGS="$CXXFLAGS $DEFINES"

CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS CC=$CC CXX=$CXX \
  /bin/bash $SRC/icu/icu4c/source/runConfigureICU Linux \
   --with-library-bits=64 --with-data-packaging=static --enable-static --disable-shared

export ASAN_OPTIONS="detect_leaks=0"
export UBSAN_OPTIONS="detect_leaks=0"

make -j$(nproc)

$CXX $CXXFLAGS -std=c++11 -c $SRC/icu/icu4c/source/test/fuzzer/locale_util.cpp \
     -I$SRC/icu4c/source/test/fuzzer

FUZZER_PATH=$SRC/icu/icu4c/source/test/fuzzer
# Assumes that all fuzzers files end with'_fuzzer.cpp'.
FUZZERS=$FUZZER_PATH/*_fuzzer.cpp

for fuzzer in $FUZZERS; do
  file=${fuzzer:${#FUZZER_PATH}+1}
  $CXX $CXXFLAGS -std=c++11 \
    $fuzzer -o $OUT/${file/.cpp/} locale_util.o \
    -I$SRC/icu/icu4c/source/common -I$SRC/icu/icu4c/source/i18n -L$WORK/icu/lib \
    $LIB_FUZZING_ENGINE -licui18n -licuuc -licutu -licudata
done

# Assumes that all seed files end with '*_fuzzer_seed_corpus.txt'.
CORPUS=$SRC/icu/icu4c/source/test/fuzzer/*_fuzzer_seed_corpus.txt
for corpus in $CORPUS; do
    zipfile=${corpus:${#FUZZER_PATH}+1}
    zip $OUT/${zipfile/.txt/.zip} $corpus
done

cp $SRC/icu/icu4c/source/test/fuzzer/*.dict  $OUT/
