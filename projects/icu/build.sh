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

FUZZERS="break_iterator_fuzzer \
  break_iterator_utf32_fuzzer \
  converter_fuzzer \
  number_format_fuzzer \
  ucasemap_fuzzer \
  unicode_string_codepage_create_fuzzer \
  uregex_open_fuzzer
  "
for fuzzer in $FUZZERS; do
  $CXX $CXXFLAGS -std=c++11 \
    $SRC/icu/icu4c/source/test/fuzzer/$fuzzer.cc -o $OUT/$fuzzer \
    -I$SRC/icu/icu4c/source/common -I$SRC/icu/icu4c/source/i18n -L$WORK/icu/lib \
    -lFuzzingEngine -licui18n -licuuc -licutu -licudata
done

cp $SRC/icu/icu4c/source/test/fuzzer/*.dict  $OUT/
