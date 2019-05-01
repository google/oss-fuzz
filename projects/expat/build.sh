#!/bin/bash -eu
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

cd expat

./buildconf.sh
./configure
make clean
make -j$(nproc) all

ENCODING_TYPES="UTF_16 \
  UTF_8 \
  ISO_8859_1 \
  US_ASCII \
  UTF_16BE \
  UTF_16LE"

for encoding in $ENCODING_TYPES; do
  fuzz_target_name=parse_${encoding}_fuzzer

  $CXX $CXXFLAGS -std=c++11 -Ilib/ -DENCODING_${encoding} \
      $SRC/parse_fuzzer.cc -o $OUT/${fuzz_target_name} \
      $LIB_FUZZING_ENGINE lib/.libs/libexpat.a

  # Use dictionaries in proper encoding for 16-bit encoding types.
  if [[ $encoding == *"UTF_16"* ]]; then
    cp $SRC/xml_${encoding}.dict  $OUT/${fuzz_target_name}.dict
  else
    cp $SRC/xml.dict  $OUT/${fuzz_target_name}.dict
  fi

  # Generate .option files for each fuzzer.
  echo -en "[libfuzzer]\ndict = ${fuzz_target_name}.dict\nmax_len = 1024\n" \
      > $OUT/${fuzz_target_name}.options
done
