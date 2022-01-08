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
env
if ! env CFLAGS="" ./configure \
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

# Build fuzzers
EXTRA_CFLAGS="-DCIPHER_NONE_AVAIL=1"
STATIC_CRYPTO="-Wl,-Bstatic -lcrypto -Wl,-Bdynamic"

SK_NULL=ssh-sk-null.o
SK_DUMMY=sk-dummy.o

$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
	regress/misc/fuzz-harness/ssh-sk-null.cc -o ssh-sk-null.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
	-DSK_DUMMY_INTEGRATE=1 regress/misc/sk-dummy/sk-dummy.c -o sk-dummy.o

$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/pubkey_fuzz.cc -o $OUT/pubkey_fuzz \
	-lssh -lopenbsd-compat $SK_NULL $STATIC_CRYPTO $LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/privkey_fuzz.cc -o $OUT/privkey_fuzz \
	-lssh -lopenbsd-compat $SK_NULL $STATIC_CRYPTO $LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/sig_fuzz.cc -o $OUT/sig_fuzz \
	-lssh -lopenbsd-compat $SK_NULL $STATIC_CRYPTO $LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/authopt_fuzz.cc -o $OUT/authopt_fuzz \
	auth-options.o -lssh -lopenbsd-compat $SK_NULL $STATIC_CRYPTO \
	$LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/sshsig_fuzz.cc -o $OUT/sshsig_fuzz \
	sshsig.o -lssh -lopenbsd-compat $SK_NULL $STATIC_CRYPTO \
	$LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/sshsigopt_fuzz.cc -o $OUT/sshsigopt_fuzz \
	sshsig.o -lssh -lopenbsd-compat $SK_NULL $STATIC_CRYPTO \
	$LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/kex_fuzz.cc -o $OUT/kex_fuzz \
	-lssh -lopenbsd-compat -lz $SK_NULL $STATIC_CRYPTO \
	$LIB_FUZZING_ENGINE

$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
	regress/misc/fuzz-harness/agent_fuzz_helper.c -o agent_fuzz_helper.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c -DENABLE_SK_INTERNAL=1 ssh-sk.c -o ssh-sk.o
$CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
	regress/misc/fuzz-harness/agent_fuzz.cc -o $OUT/agent_fuzz \
	$SK_DUMMY agent_fuzz_helper.o ssh-sk.o -lssh -lopenbsd-compat -lz \
	$STATIC_CRYPTO $LIB_FUZZING_ENGINE

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
