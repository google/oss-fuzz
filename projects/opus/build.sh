#!/bin/bash
# Copyright 2017 Google Inc.
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
##############################################################################
set -eu

FUZZERS="opus_decode_fuzzer.c opus_multi_fuzzer.cc"
BUILDS=(floating fixed)

tar xvf $SRC/opus_testvectors.tar.gz

if [[ $CFLAGS = *sanitize=memory* ]]; then
  CFLAGS+=" -D_FORTIFY_SOURCE=0"
fi

./autogen.sh

for build in "${BUILDS[@]}"; do
  case "$build" in
    floating)
      extra_args=""
      ;;
    fixed)
      extra_args=" --enable-fixed-point --enable-check-asm"
      ;;
  esac

  ./configure $extra_args --enable-static --disable-shared --disable-doc
  make -j$(nproc)

  # Build all fuzzers
  for fuzzer in $FUZZERS; do
    fuzzer_basename=$(echo $fuzzer | cut -f 1 -d '.')

    if [ ${fuzzer: -2} == ".c" ]; then
      $CC $CFLAGS -c -Iinclude \
        tests/$fuzzer \
        -o $fuzzer_basename.o

      $CXX $CXXFLAGS \
        $fuzzer_basename.o \
        -o $OUT/${fuzzer_basename}_${build} \
        $LIB_FUZZING_ENGINE .libs/libopus.a
    else
      $CXX $CXXFLAGS -Iinclude \
        tests/$fuzzer \
        -o $OUT/${fuzzer_basename}_${build} \
        $LIB_FUZZING_ENGINE .libs/libopus.a
    fi

    # Setup the .options and test corpus zip files using the corresponding
    # fuzzer's name
    cp tests/$fuzzer_basename.options $OUT/${fuzzer_basename}_${build}.options
    zip -r $OUT/${fuzzer_basename}_${build}_seed_corpus.zip opus_testvectors/
  done
done
