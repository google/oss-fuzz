#!/bin/bash -eu
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

./autogen.sh
./configure --enable-static --disable-shared --disable-doc --enable-assertions
make -j$(nproc)
ldconfig

for fuzzer in $SRC/*_fuzzer.c; do
  fuzzer_basename=$(basename -s .c $fuzzer)

  $CC $CFLAGS -c \
      -I $SRC -I /usr/include/opus -I /usr/include/ogg \
      $fuzzer -o ${fuzzer_basename}.o

  $CXX $CXXFLAGS \
      ${fuzzer_basename}.o \
      -o $OUT/${fuzzer_basename} $LIB_FUZZING_ENGINE \
      $SRC/opusfile/.libs/libopusfile.a -l:libopus.a -l:libogg.a
done
