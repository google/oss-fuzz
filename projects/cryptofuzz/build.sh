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

# Compile Openssl (with assembly)
cd $SRC/openssl
./config --debug enable-md2 enable-rc5
make -j$(nproc)

export CXXFLAGS="$CXXFLAGS -I $SRC/cryptofuzz/fuzzing-headers/include"

# Compile Cryptofuzz OpenSSL (with assembly) module
cd $SRC/cryptofuzz/modules/openssl
OPENSSL_INCLUDE_PATH="$SRC/openssl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/openssl/libcrypto.a" make

# Compile Cryptofuzz
cd $SRC/cryptofuzz
LIBFUZZER_LINK="-lFuzzingEngine" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include" make -j$(nproc)

# Generate dictionary
./generate_dict

# Copy fuzzer
cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-openssl
# Copy dictionary
cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-openssl.dict
# Copy seed corpus
cp $SRC/cryptofuzz-corpora/openssl_latest.zip $OUT/cryptofuzz-openssl_seed_corpus.zip

# Compile Openssl (without assembly)
cd $SRC/openssl
make clean
./config --debug no-asm enable-md2 enable-rc5
make -j$(nproc)

# Compile Cryptofuzz OpenSSL (without assembly) module
cd $SRC/cryptofuzz/modules/openssl
OPENSSL_INCLUDE_PATH="$SRC/openssl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/openssl/libcrypto.a" make -B

# Compile Cryptofuzz
cd $SRC/cryptofuzz
LIBFUZZER_LINK="-lFuzzingEngine" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include" make -B -j$(nproc)

# Copy fuzzer
cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-openssl-noasm
# Copy dictionary
cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-openssl-noasm.dict
# Copy seed corpus
cp $SRC/cryptofuzz-corpora/openssl_latest.zip $OUT/cryptofuzz-openssl-noasm_seed_corpus.zip
