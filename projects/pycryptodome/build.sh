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

PCD_INTERNALS=(src/*.c src/libtom/*.c)
PCD_FLAGS=(
  "-I $SRC/pycryptodome/src"
  "-I $SRC/pycryptodome/src/libtom"
  "-D HAVE_STDINT_H"
  "-D HAVE_MEMALIGN"
  "-D HAVE_INTRIN_H"
  "-D SYS_BITS=$(getconf LONG_BIT)"
  "-maes -msse2 -mpclmul"
)

$CC $CFLAGS \
    ${PCD_FLAGS[@]} \
    -c "${PCD_INTERNALS//'blake2.c'/}"
ar -qc $WORK/libpycryptodome.a  *.o

PCD_HASH_FUNCTION_PREFIXES=(
  "md2"
  "md4"
  "MD5"
  "ripemd160"
  "SHA224"
  "SHA256"
  "SHA384"
  # "keccak"
)

PCD_HASH_FNAMES=(
  "MD2.c"
  "MD4.c"
  "MD5.c"
  "RIPEMD160.c"
  "SHA224.c"
  "SHA256.c"
  "SHA384.c"
)

PCD_HASH_DIGEST_SETTINGS=(
  "-D DIGEST_SIZE=16"
  "-D DIGEST_SIZE=16"
  ""
  "-D DIGEST_SIZE=RIPEMD160_DIGEST_SIZE"
  "-D DIGEST_THIRD_PARAM"
  "-D DIGEST_THIRD_PARAM"
  "-D DIGEST_THIRD_PARAM"
)

for i in {0..6}; do
  $CXX $CXXFLAGS ${PCD_FLAGS[@]} \
      -D HASHTYPE=${PCD_HASH_FUNCTION_PREFIXES[$i]} \
      -D FNAME=${PCD_HASH_FNAMES[$i]} \
      ${PCD_HASH_DIGEST_SETTINGS[$i]} \
      $SRC/pcd_hash_fuzzer.cc \
      $LIB_FUZZING_ENGINE $WORK/libpycryptodome.a \
      -o $OUT/${PCD_HASH_FUNCTION_PREFIXES[$i]}_fuzzer
done
