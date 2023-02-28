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

# build project (default configuration + experimental features)
scripts/config.py full
# Allow repeatability of time-based calculations.
scripts/config.py set MBEDTLS_PLATFORM_TIME_ALT
# MBEDTLS_USE_PSA_CRYPTO significantly changes how X.509 and TLS work.
# In this build, use the default setting.
scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
mkdir build
cd build
cmake -DENABLE_TESTING=OFF ..
# build including fuzzers
make -j$(nproc) all
cp programs/fuzz/fuzz_* $OUT/
cd ..

# build corpuses
cd programs
cp -r ../../openssl/fuzz/corpora/crl fuzz/corpuses/
cp -r ../../openssl/fuzz/corpora/x509 fuzz/corpuses/
cp -r ../../boringssl/fuzz/privkey_corpus fuzz/corpuses/
cp ../../boringssl/fuzz/cert_corpus/* fuzz/corpuses/x509/
zip -r fuzz/fuzz_x509crl_seed_corpus.zip ../tests/data_files/crl* fuzz/corpuses/crl
zip -r fuzz/fuzz_x509crt_seed_corpus.zip ../tests/data_files/*.crt ../tests/data_files/dir*/*.crt  fuzz/corpuses/x509/
zip -r fuzz/fuzz_x509csr_seed_corpus.zip ../tests/data_files/*.csr ../tests/data_files/*.req.*
zip -r fuzz/fuzz_privkey_seed_corpus.zip ../tests/data_files/*.key ../tests/data_files/*.pem fuzz/corpuses/privkey_corpus
zip -r fuzz/fuzz_pubkey_seed_corpus.zip ../tests/data_files/*.pub ../tests/data_files/*.pubkey
zip -r fuzz/fuzz_dtlsclient_seed_corpus.zip fuzz/corpuses/dtlsclient
zip -r fuzz/fuzz_dtlsserver_seed_corpus.zip fuzz/corpuses/dtlsserver
zip -r fuzz/fuzz_client_seed_corpus.zip fuzz/corpuses/client
zip -r fuzz/fuzz_server_seed_corpus.zip fuzz/corpuses/server
cd fuzz
# export other associated stuff
cp *.options $OUT/
cp fuzz_*_seed_corpus.zip $OUT/
cd ../..

# build project (some non-default compile-time settings)
scripts/config.py full
# Allow repeatability of time-based calculations.
scripts/config.py set MBEDTLS_PLATFORM_TIME_ALT
# Toggle some options that affect how some parts of the library work.
scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
scripts/config.py set MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED
scripts/config.py set MBEDTLS_RSA_NO_CRT
mkdir build-usepsa
cd build-usepsa
cmake -DENABLE_TESTING=OFF ..
# just build the fuzzers
make -j$(nproc) -C programs/fuzz
cd programs/fuzz
for x in fuzz_*; do
  cp $x $OUT/usepsa-$x
  # use the same ancilliary data as the default-build executables
  if [ -e $OUT/${x}_seed_corpus.zip ]; then
    ln -s ${x}_seed_corpus.zip $OUT/usepsa-${x}_seed_corpus.zip
  fi
  if [ -e $OUT/${x}.options ]; then
    ln -s ${x}.options $OUT/usepsa-${x}.options
  fi
done
cd ../..
cd ..
