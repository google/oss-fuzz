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

mkdir build
cd build
cmake ..
make -j$(nproc) h3

H3_BASE=/src/h3/

for fuzzer in $(find $H3_BASE/src/apps/fuzzers -name '*.c'); do
  fuzzer_basename=$(basename -s .c $fuzzer)
  # H3_USE_LIBFUZZER is needed so that H3 does not try to build its own
  # implementation of `main`
  $CC $CFLAGS -DH3_PREFIX="" \
    -DH3_USE_LIBFUZZER=1 \
    -I$H3_BASE/src/apps/applib/include \
    -I$H3_BASE/src/h3lib/include \
    -I$H3_BASE/build/src/h3lib/include \
    -o $fuzzer_basename.o \
    -c $fuzzer

  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -rdynamic \
    $fuzzer_basename.o \
    -o $OUT/$fuzzer_basename \
    lib/libh3.a
done
