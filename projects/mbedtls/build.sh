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
# TODO change when merged into master branch of official repo
git apply ../fuzz.diff
cmake .
make -j$(nproc) all

# build corpuses
cd tests
cp -r ../../openssl/fuzz/corpora/crl fuzz/corpuses/
cp -r ../../openssl/fuzz/corpora/x509 fuzz/corpuses/
cp -r ../../boringssl/fuzz/privkey_corpus fuzz/corpuses/
cp ../../boringssl/fuzz/cert_corpus/* fuzz/corpuses/x509/
zip -r fuzz/fuzz_x509crl_seed_corpus.zip data_files/crl* fuzz/corpuses/crl
zip -r fuzz/fuzz_x509crt_seed_corpus.zip data_files/*.crt data_files/dir*/*.crt  fuzz/corpuses/x509/
zip -r fuzz/fuzz_x509csr_seed_corpus.zip data_files/*.csr data_files/*.req.*
zip -r fuzz/fuzz_privkey_seed_corpus.zip data_files/*.key data_files/*.pem fuzz/corpuses/privkey_corpus
zip -r fuzz/fuzz_pubkey_seed_corpus.zip data_files/*.pub data_files/*.pubkey data_files/*pub.pem
zip -r fuzz/fuzz_dtlsclient_seed_corpus.zip fuzz/corpuses/dtlsclient
zip -r fuzz/fuzz_dtlsserver_seed_corpus.zip fuzz/corpuses/dtlsserver
zip -r fuzz/fuzz_client_seed_corpus.zip fuzz/corpuses/client
zip -r fuzz/fuzz_server_seed_corpus.zip fuzz/corpuses/server

cd fuzz
# export other associated stuff
cp *.options $OUT/
cp fuzz_*_seed_corpus.zip $OUT/

# build fuzzers
for target in x509crl x509crt x509csr privkey pubkey client server dtlsclient dtlsserver
do
    $CC $CFLAGS -I. -I ../../include -c fuzz_$target.c -o fuzz_$target.o

    $CXX $CXXFLAGS -std=c++11 fuzz_$target.o -o $OUT/fuzz_$target ../../library/libmbedx509.a ../../library/libmbedtls.a ../../library/libmbedcrypto.a $LIB_FUZZING_ENGINE
done
