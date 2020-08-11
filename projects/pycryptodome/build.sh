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
PYCRYPTODOME_FLAGS=(
  "-I $SRC/pycryptodome/src"
  "-I $SRC/pycryptodome/src/libtom"
  "-D HAVE_STDINT_H"
  "-D HAVE_MEMALIGN"
  "-D HAVE_INTRIN_H"
  "-D SYS_BITS=$(getconf LONG_BIT)"
  "-maes -msse2 -mpclmul"
)

$CC $CFLAGS \
    ${PYCRYPTODOME_FLAGS[@]} \
    -c "${PYCRYPTODOME_INTERNALS//'blake2.c'/}"
ar -qc $WORK/libpycryptodome.a  *.o

for fuzzer in $SRC/*_fuzzer.cc; do
  fuzzer_basename=$(basename -s .cc $fuzzer)

  # $CC $CFLAGS \
  #     ${PYCRYPTODOME_FLAGS[@]} \
  #     -c $fuzzer -o ${fuzzer_basename}.o

  $CXX $CXXFLAGS ${PYCRYPTODOME_FLAGS[@]} \
      $fuzzer -o $OUT/$fuzzer_basename \
      $LIB_FUZZING_ENGINE $WORK/libpycryptodome.a
done
