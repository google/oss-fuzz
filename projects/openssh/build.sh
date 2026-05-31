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

# authkeys seed corpus: sample authorized_keys lines (keys embedded in harness)
mkdir -p /tmp/authkeys_corpus
cp regress/misc/fuzz-harness/testdata/id_ed25519.pub /tmp/authkeys_corpus/ 2>/dev/null || true
cp regress/misc/fuzz-harness/testdata/id_ecdsa.pub /tmp/authkeys_corpus/ 2>/dev/null || true
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD user@host\n' > /tmp/authkeys_corpus/plain.pub
printf 'from="192.168.1.*",command="/bin/sh" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD restricted\n' > /tmp/authkeys_corpus/restricted.pub
printf 'no-pty,no-x11-forwarding,no-agent-forwarding ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA3I user@host\n' > /tmp/authkeys_corpus/no-opts.pub
(cd /tmp/authkeys_corpus && zip -r $OUT/authkeys_fuzz_seed_corpus.zip .)

# sshconfig seed corpus: sample ssh_config snippets
mkdir -p /tmp/sshconfig_corpus
cat > /tmp/sshconfig_corpus/basic.conf << 'CONF'
Host example.com
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking yes
CONF
cat > /tmp/sshconfig_corpus/match.conf << 'CONF'
Match Host *.internal exec "test -f /etc/flag"
    ProxyJump bastion.example.com
    IdentityFile ~/.ssh/internal_key
    ServerAliveInterval 60
CONF
cat > /tmp/sshconfig_corpus/wildcard.conf << 'CONF'
Host *
    AddKeysToAgent yes
    ForwardAgent no
    Compression yes
    ConnectTimeout 30
    ServerAliveCountMax 3
CONF
cp $SRC/openssh/ssh_config /tmp/sshconfig_corpus/system.conf 2>/dev/null || true
(cd /tmp/sshconfig_corpus && zip -r $OUT/sshconfig_fuzz_seed_corpus.zip .)