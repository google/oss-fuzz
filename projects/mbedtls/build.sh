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

# build project
cmake .
make -j$(nproc) all

# build corpuses
cd tests
zip -r fuzz/fuzz_x509crl_seed_corpus.zip data_files/crl*
zip -r fuzz/fuzz_x509crt_seed_corpus.zip data_files/*.crt data_files/dir*/*.crt fuzz/corpuses/x509/*
zip -r fuzz/fuzz_x509csr_seed_corpus.zip data_files/*.csr data_files/*.req.*
zip -r fuzz/fuzz_privkey_seed_corpus.zip data_files/*.key data_files/*.pem
zip -r fuzz/fuzz_pubkey_seed_corpus.zip data_files/*.pub data_files/*.pubkey data_files/*pub.pem

cd fuzz
# export other associated stuff
cp *.options $OUT/
cp fuzz_*_seed_corpus.zip $OUT/

# build fuzzers
$CC $CFLAGS -I. -I ../../include -c fuzz_x509crl.c -o fuzz_x509crl.o

$CXX $CXXFLAGS -std=c++11 fuzz_x509crl.o -o $OUT/fuzz_x509crl ../../library/libmbedx509.a ../../library/libmbedtls.a ../../library/libmbedcrypto.a -lFuzzingEngine

$CC $CFLAGS -I. -I ../../include -c fuzz_x509crt.c -o fuzz_x509crt.o

$CXX $CXXFLAGS -std=c++11 fuzz_x509crt.o -o $OUT/fuzz_x509crt ../../library/libmbedx509.a ../../library/libmbedtls.a ../../library/libmbedcrypto.a -lFuzzingEngine

$CC $CFLAGS -I. -I ../../include -c fuzz_x509csr.c -o fuzz_x509csr.o

$CXX $CXXFLAGS -std=c++11 fuzz_x509csr.o -o $OUT/fuzz_x509csr ../../library/libmbedx509.a ../../library/libmbedtls.a ../../library/libmbedcrypto.a -lFuzzingEngine

$CC $CFLAGS -I. -I ../../include -c fuzz_privkey.c -o fuzz_privkey.o

$CXX $CXXFLAGS -std=c++11 fuzz_privkey.o -o $OUT/fuzz_privkey ../../library/libmbedx509.a ../../library/libmbedtls.a ../../library/libmbedcrypto.a -lFuzzingEngine

$CC $CFLAGS -I. -I ../../include -c fuzz_pubkey.c -o fuzz_pubkey.o

$CXX $CXXFLAGS -std=c++11 fuzz_pubkey.o -o $OUT/fuzz_pubkey ../../library/libmbedx509.a ../../library/libmbedtls.a ../../library/libmbedcrypto.a -lFuzzingEngine

$CC $CFLAGS -I. -I ../../include -c fuzz_client.c -o fuzz_client.o

$CXX $CXXFLAGS -std=c++11 fuzz_client.o -o $OUT/fuzz_client ../../library/libmbedx509.a ../../library/libmbedtls.a ../../library/libmbedcrypto.a -lFuzzingEngine

$CC $CFLAGS -I. -I ../../include -c fuzz_server.c -o fuzz_server.o

$CXX $CXXFLAGS -std=c++11 fuzz_server.o -o $OUT/fuzz_server ../../library/libmbedx509.a ../../library/libmbedtls.a ../../library/libmbedcrypto.a -lFuzzingEngine
