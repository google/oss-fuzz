#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Build libcbor, taken from oss-fuzz/projects/libcbor/build.sh
# Note SANITIZE=OFF since it gets taken care of by $CFLAGS set by oss-fuzz
cd ${SRC}/libcbor
patch -l -p0 < ${SRC}/libfido2/fuzz/README
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_INSTALL_PREFIX=${WORK} -DSANITIZE=OFF ..
make -j$(nproc) VERBOSE=1
make install

# Build OpenSSL, taken from oss-fuzz/projects/openssl/build.sh
cd ${SRC}/openssl
CONFIGURE_FLAGS=""
if [[ ${SANITIZER} = memory ]]
then
  CONFIGURE_FLAGS="no-asm"
fi
./config --debug no-tests ${CFLAGS} --prefix=${WORK} \
	 --openssldir=${WORK}/openssl ${CONFIGURE_FLAGS}
make -j$(nproc) LDCMD="${CXX} ${CXXFLAGS}"
make install_sw

# Build zlib, taken from oss-fuzz/projects/zlib.sh
cd ${SRC}/zlib
./configure --prefix=${WORK}
make -j$(nproc) all
make install

# Building libfido2 with ${LIB_FUZZING_ENGINE} and chosen sanitizer
cd ${SRC}/libfido2
mkdir build && cd build
cmake -DFUZZ=1 -DFUZZ_LDFLAGS=${LIB_FUZZING_ENGINE} \
      -DPKG_CONFIG_USE_CMAKE_PREFIX_PATH=1 \
      -DCMAKE_PREFIX_PATH=${WORK} \
      -DCMAKE_INSTALL_PREFIX=${WORK} \
      -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
make install

# Prepare ${OUT} with instrumented libs
mkdir -p ${OUT}/lib
for lib in `ls ${WORK}/lib/lib*.so*`; do
    cp ${lib} ${OUT}/lib;
done

# Fixup rpath in the fuzzers so they use our libs
for f in `ls fuzz/fuzz_*`; do
    cp ${f} ${OUT}/
    fuzzer=$(basename $f)
    chrpath -r '$ORIGIN/lib' ${OUT}/${fuzzer}
done

 # Prepare seed corpora
tar xzf ${SRC}/corpus.tgz
(set -e ; cd fuzz_assert/corpus    ; zip -r ${OUT}/fuzz_assert_seed_corpus.zip .)
(set -e ; cd fuzz_bio/corpus       ; zip -r ${OUT}/fuzz_bio_seed_corpus.zip .)
(set -e ; cd fuzz_cred/corpus      ; zip -r ${OUT}/fuzz_cred_seed_corpus.zip .)
(set -e ; cd fuzz_credman/corpus   ; zip -r ${OUT}/fuzz_credman_seed_corpus.zip .)
(set -e ; cd fuzz_hid/corpus       ; zip -r ${OUT}/fuzz_hid_seed_corpus.zip .)
(set -e ; cd fuzz_largeblob/corpus ; zip -r ${OUT}/fuzz_largeblob_seed_corpus.zip .)
(set -e ; cd fuzz_mgmt/corpus      ; zip -r ${OUT}/fuzz_mgmt_seed_corpus.zip .)
(set -e ; cd fuzz_netlink/corpus   ; zip -r ${OUT}/fuzz_netlink_seed_corpus.zip .)
(set -e ; cd fuzz_pcsc/corpus      ; zip -r ${OUT}/fuzz_pcsc_seed_corpus.zip .)
