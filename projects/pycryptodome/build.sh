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

patch block_common.c block_common.patch

PCD_INTERNALS=(./*.c ./libtom/*.c)
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
ar -qc $WORK/libpycryptodome.a *.o

PCD_HASH_OPTIONS=(
  "-D HASHTYPE=md2 -D FNAME=MD2.c -D DIGEST_SIZE=16 -o $OUT/md2_fuzzer"
  "-D HASHTYPE=md4 -D FNAME=MD4.c -D DIGEST_SIZE=16 -o $OUT/md4_fuzzer"
  "-D HASHTYPE=MD5 -D FNAME=MD5.c -o $OUT/md5_fuzzer"
  "-D HASHTYPE=ripemd160 -D FNAME=RIPEMD160.c -D DIGEST_SIZE=RIPEMD160_DIGEST_SIZE -o $OUT/ripemd160_fuzzer"
  "-D HASHTYPE=SHA224 -D FNAME=SHA224.c -D DIGEST_THIRD_PARAM -o $OUT/sha224_fuzzer"
  "-D HASHTYPE=SHA256 -D FNAME=SHA256.c -D DIGEST_THIRD_PARAM -o $OUT/sha256_fuzzer"
  "-D HASHTYPE=SHA384 -D FNAME=SHA384.c -D DIGEST_THIRD_PARAM -o $OUT/sha384_fuzzer"
)

for ((i = 0; i < ${#PCD_HASH_OPTIONS[@]}; i++)); do
  $CXX $CXXFLAGS ${PCD_FLAGS[@]} \
      $SRC/pcd_hash_fuzzer.cc ${PCD_HASH_OPTIONS[i]} \
      $LIB_FUZZING_ENGINE $WORK/libpycryptodome.a
done

$CXX $CXXFLAGS ${PCD_FLAGS[@]} \
    $SRC/pcd_aes_fuzzer.cc -o $OUT/aes_fuzzer \
    $LIB_FUZZING_ENGINE $WORK/libpycryptodome.a
