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

FUZZERS="opus_encode_fuzzer opus_multistream_decode_fuzzer opus_multistream_encode_fuzzer opus_projection_decoder_fuzzer opus_projection_encoder_fuzzer opus_repacketizer_fuzzer"
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

  ./configure $extra_args --enable-static --disable-shared --disable-doc \
    --enable-assertions
  make -j$(nproc)

  # Build all fuzzers
  for fuzzer in $FUZZERS; do
    $CXX $CXXFLAGS -c -Iinclude \
      tests/$fuzzer.cc \
      -o $fuzzer.o

    $CXX $CXXFLAGS \
      $fuzzer.o \
      -o $OUT/${fuzzer}_${build} \
      $LIB_FUZZING_ENGINE .libs/libopus.a

    # Setup the .options and test corpus zip files using the corresponding
    # fuzzer's name
    [ -f tests/$fuzzer.options ] \
        && cp tests/$fuzzer.options $OUT/${fuzzer}_${build}.options
    zip -r $OUT/${fuzzer}_${build}_seed_corpus.zip opus_testvectors/
  done
done
