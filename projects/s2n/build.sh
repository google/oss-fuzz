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

# OpenSSL build script
cd ${SRC}/openssl
CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]]
then
  CONFIGURE_FLAGS="no-asm"
fi

./config --debug no-tests ${CFLAGS} --prefix=${WORK} \
         --openssldir=${WORK}/openssl ${CONFIGURE_FLAGS}
make -j$(nproc) LDCMD="${CXX} ${CXXFLAGS}"
make install_sw

# s2n build script with LIB_FUZZING_ENGINE
cd ${SRC}/s2n
export LIBCRYPTO_ROOT=${WORK}
export S2N_ROOT=${SRC}/s2n
git apply ../libfuzzer_engine.diff

# Rename *_test.c to *_test.cc, we do this because clang++-12 doesnt support file with C extension
FUZZERS=`ls tests/fuzz/*_test.c`
for f in $FUZZERS; do
  cp $f ${f}c
done

make fuzz -j$(nproc)
cp tests/fuzz/*.c ${OUT}/
cp tests/fuzz/*_test ${OUT}

FUZZERS=`ls tests/fuzz/*_test`
printf "Detected fuzzers: \n$FUZZERS\n"
for f in $FUZZERS; do
  fuzz_name=$(basename $f)
  patchelf --set-rpath '$ORIGIN/lib' "${OUT}/$fuzz_name" || echo "patchelf failed with $?, ignoring."
done

for f in `ls tests/fuzz/corpus`; do
  corpus_zip="${f}_seed_corpus.zip"
  zip "${OUT}/${corpus_zip}" tests/fuzz/corpus/$f/*
done

mkdir -p "${OUT}/lib"
cp ${SRC}/openssl/libcrypto.so.1.1 ${OUT}/lib
cp ${SRC}/s2n/lib/libs2n.so ${OUT}/lib
cp ${SRC}/s2n/tests/testlib/libtests2n.so ${OUT}/lib
