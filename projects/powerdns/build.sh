#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# remove dependencies on boost's program_options, we don't need it
# and it won't link because oss-fuzz adds -stdlib=libc++ to the flags,
# which would require rebuilding boost
sed -i 's/BOOST_PROGRAM_OPTIONS(\[mt\])//' configure.ac
sed -i 's/AC_MSG_ERROR(\[Boost Program Options library not found\])/AC_MSG_NOTICE(\[Boost Program Options library not found\])/' configure.ac
# we also need to disable building as PIE because libFuzzingEngine.a
# does not appear to be compiled as PIC
sed -i 's/AC_CC_PIE//' configure.ac

# build fuzzing targets
autoreconf -vi
./configure \
    --without-dynmodules \
    --with-modules='' \
    --disable-lua-records \
    --disable-ixfrdist \
    --enable-fuzz-targets \
    --disable-dependency-tracking \
    --disable-silent-rules || /bin/bash
make -j$(nproc) -C ext/yahttp/
cd pdns
make -j$(nproc) fuzz_targets

# copy the fuzzing target binaries
cp fuzz_target_* "${OUT}/"

# copy the zones used in the regression tests to the "zones" corpus
cp ../regression-tests/zones/* ../fuzzing/corpus/zones/

# generate the corpus files
if [ -d ../fuzzing/corpus/raw-dns-packets/ ]; then
    zip -j "${OUT}/fuzz_target_dnsdistcache_seed_corpus.zip" ../fuzzing/corpus/raw-dns-packets/*
fi
if [ -d ../fuzzing/corpus/txt-records/ ]; then
    zip -j "${OUT}/fuzz_target_dnslabeltext_parseRFC1035CharString_seed_corpus.zip" ../fuzzing/corpus/txt-records/*
fi
if [ -d ../fuzzing/corpus/raw-dns-packets/ ]; then
    zip -j "${OUT}/fuzz_target_moadnsparser_seed_corpus.zip" ../fuzzing/corpus/raw-dns-packets/*
fi
if [ -d ../fuzzing/corpus/raw-dns-packets/ ]; then
    zip -j "${OUT}/fuzz_target_packetcache_seed_corpus.zip" ../fuzzing/corpus/raw-dns-packets/*
fi
if [ -d ../fuzzing/corpus/proxy-protocol-raw-packets/ ]; then
    zip -j "${OUT}/fuzz_target_proxyprotocol_seed_corpus.zip" ../fuzzing/corpus/proxy-protocol-raw-packets/*
fi
if [ -d ../fuzzing/corpus/zones/ ]; then
    zip -j "${OUT}/fuzz_target_zoneparsertng_seed_corpus.zip" ../fuzzing/corpus/zones/*
fi
if [ -d ../fuzzing/corpus/http-raw-payloads/ ]; then
    zip -j "${OUT}/fuzz_target_yahttp_seed_corpus.zip" ../fuzzing/corpus/http-raw-payloads/*
fi
