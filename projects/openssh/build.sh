#!/bin/bash -eu
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
################################################################################

# Enable null cipher
sed -i 's/#define CFLAG_INTERNAL.*/#define CFLAG_INTERNAL 0/' cipher.c

# Turn off agent unlock password failure delays
sed -i 's|\(usleep.*\)|// \1|' ssh-agent.c

# Build project
autoreconf
if ! env CFLAGS="" ./configure \
    --without-hardening \
    --without-zlib-version-check \
    --with-cflags="-DWITH_XMSS=1" \
    --with-cflags-after="$CFLAGS" \
    --with-ldflags-after="-g $CFLAGS" ; then
	echo "------ config.log:" 1>&2
	cat config.log 1>&2
	echo "ERROR: configure failed" 1>&2
	exit 1
fi
make -j$(nproc) all

# Build fuzzers using upstream Makefile
FUZZER_TARGETS=$(cd regress/misc/fuzz-harness && ls *_fuzz.cc 2>/dev/null | grep -v sntrup761 | sed 's/\.cc$//' | tr '\n' ' ')
make -C regress/misc/fuzz-harness $FUZZER_TARGETS \
	CC="$CC" \
	CXX="$CXX" \
	CFLAGS="-D_GNU_SOURCE=1 -DCIPHER_NONE_AVAIL=1 -I ../../.. -I ../../../openbsd-compat/include $CFLAGS" \
	CXXFLAGS="-D_GNU_SOURCE=1 -DCIPHER_NONE_AVAIL=1 -I ../../.. -I ../../../openbsd-compat/include $CXXFLAGS" \
	FUZZ_FLAGS="$CXXFLAGS" \
	FUZZ_LIBS="$LIB_FUZZING_ENGINE" \
	COMMON_OBJS="../../../ssh-pkcs11-client.o" \
	LIBS="../../../ssh-pkcs11-client.o -lssh -lopenbsd-compat -Wl,-Bstatic -lcrypto -Wl,-Bdynamic \$(FUZZ_LIBS)"

# Copy all fuzzers to output directory
cp regress/misc/fuzz-harness/*_fuzz $OUT/

# Prepare seed corpora
CASES="$SRC/openssh-fuzz-cases"
(set -e ; cd ${CASES}/key ; zip -r $OUT/pubkey_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/privkey ; zip -r $OUT/privkey_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/sig ; zip -r $OUT/sig_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/authopt ; zip -r $OUT/authopt_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/sshsig ; zip -r $OUT/sshsig_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/sshsigopt ; zip -r $OUT/sshsigopt_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/kex ; zip -r $OUT/kex_fuzz_seed_corpus.zip .)
(set -e ; cd ${CASES}/agent ; zip -r $OUT/agent_fuzz_seed_corpus.zip .)