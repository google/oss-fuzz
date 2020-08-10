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

PYCRYPTODOME_INTERNALS=(src/*.c src/libtom/*.c)

# TODO(rjotwani): Find out how to get system bits from command line
$CC $CFLAGS -I ./src -I ./src/libtom \
    -DHAVE_STDINT_H -DHAVE_MEMALIGN -DHAVE_INTRIN_H \
    -DSYS_BITS=$(getconf LONG_BIT) -maes -msse2 -mpclmul \
    -c "${PYCRYPTODOME_INTERNALS//'blake2.c'/}"
ar -qc $WORK/libpycryptodome.a  *.o

for fuzzer in $SRC/*_fuzzer.c; do
  fuzzer_basename=$(basename -s .c $fuzzer)

  $CC $CFLAGS \
      -I ./src -I ./src/libtom \
      $fuzzer -c -o ${fuzzer_basename}.o

  $CXX $CXXFLAGS \
      ${fuzzer_basename}.o -o $OUT/$fuzzer_basename \
      $LIB_FUZZING_ENGINE $WORK/libpycryptodome.a
done
