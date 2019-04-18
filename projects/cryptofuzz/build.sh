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

# TODO(metzman): Switch this to LIB_FUZZING_ENGINE when it works.
# https://github.com/google/oss-fuzz/issues/2336

# Generate lookup tables. This only needs to be done once.
cd $SRC/cryptofuzz
python gen_repository.py

cd $SRC/openssl

export CXXFLAGS="$CXXFLAGS -I $SRC/cryptofuzz/fuzzing-headers/include"
if [[ $CFLAGS = *sanitize=memory* ]]
then
    export CXXFLAGS="$CXXFLAGS -DMSAN"
fi

##############################################################################
if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile LibreSSL (with assembly)
    cd $SRC/libressl
    rm -rf build ; mkdir build
    cd build
    cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" ..
    make -j$(nproc) crypto

    # Compile Cryptofuzz LibreSSL (with assembly) module
    cd $SRC/cryptofuzz/modules/openssl
    OPENSSL_INCLUDE_PATH="$SRC/libressl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/libressl/build/crypto/libcrypto.a" CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBRESSL" make -B

    # Compile Cryptofuzz
    cd $SRC/cryptofuzz
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE_DEPRECATED" CXXFLAGS="$CXXFLAGS -I $SRC/libressl/include -DCRYPTOFUZZ_LIBRESSL" make -B -j$(nproc)

    # Generate dictionary
    ./generate_dict

    # Copy fuzzer
    cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-libressl
    # Copy dictionary
    cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-libressl.dict
    # Copy seed corpus
    cp $SRC/cryptofuzz-corpora/libressl_latest.zip $OUT/cryptofuzz-libressl_seed_corpus.zip
fi

##############################################################################
if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile Openssl (with assembly)
    cd $SRC/openssl
    ./config --debug enable-md2 enable-rc5
    make || true

    # Compile Cryptofuzz OpenSSL (with assembly) module
    cd $SRC/cryptofuzz/modules/openssl
    OPENSSL_INCLUDE_PATH="$SRC/openssl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/openssl/libcrypto.a" make -B

    # Compile Cryptofuzz
    cd $SRC/cryptofuzz
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE_DEPRECATED" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include" make -B -j$(nproc)

    # Generate dictionary
    ./generate_dict

    # Copy fuzzer
    cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-openssl
    # Copy dictionary
    cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-openssl.dict
    # Copy seed corpus
    cp $SRC/cryptofuzz-corpora/openssl_latest.zip $OUT/cryptofuzz-openssl_seed_corpus.zip
fi

##############################################################################
# Compile Openssl (without assembly)
cd $SRC/openssl
./config --debug no-asm enable-md2 enable-rc5
make clean
make || true

# Compile Cryptofuzz OpenSSL (without assembly) module
cd $SRC/cryptofuzz/modules/openssl
OPENSSL_INCLUDE_PATH="$SRC/openssl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/openssl/libcrypto.a" make -B

# Compile Cryptofuzz
cd $SRC/cryptofuzz
LIBFUZZER_LINK="$LIB_FUZZING_ENGINE_DEPRECATED" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include" make -B -j$(nproc)

# Generate dictionary
./generate_dict

# Copy fuzzer
cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-openssl-noasm
# Copy dictionary
cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-openssl-noasm.dict
# Copy seed corpus
cp $SRC/cryptofuzz-corpora/openssl_latest.zip $OUT/cryptofuzz-openssl-noasm_seed_corpus.zip

##############################################################################
if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile BoringSSL (with assembly)
    cd $SRC/boringssl
    rm -rf build ; mkdir build
    cd build
    cmake -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" -DBORINGSSL_ALLOW_CXX_RUNTIME=1 ..
    make -j$(nproc) crypto

    # Compile Cryptofuzz BoringSSL (with assembly) module
    cd $SRC/cryptofuzz/modules/openssl
    OPENSSL_INCLUDE_PATH="$SRC/boringssl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/boringssl/build/crypto/libcrypto.a" CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BORINGSSL" make -B

    # Compile Cryptofuzz
    cd $SRC/cryptofuzz
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE_DEPRECATED" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include" make -B -j$(nproc)

    # Generate dictionary
    ./generate_dict

    # Copy fuzzer
    cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-boringssl
    # Copy dictionary
    cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-boringssl.dict
    # Copy seed corpus
    cp $SRC/cryptofuzz-corpora/boringssl_latest.zip $OUT/cryptofuzz-boringssl_seed_corpus.zip
fi

##############################################################################
# Compile BoringSSL (with assembly)
cd $SRC/boringssl
rm -rf build ; mkdir build
cd build
cmake -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" -DBORINGSSL_ALLOW_CXX_RUNTIME=1 -DOPENSSL_NO_ASM=1 ..
make -j$(nproc) crypto

# Compile Cryptofuzz BoringSSL (with assembly) module
cd $SRC/cryptofuzz/modules/openssl
OPENSSL_INCLUDE_PATH="$SRC/boringssl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/boringssl/build/crypto/libcrypto.a" CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BORINGSSL" make -B

# Compile Cryptofuzz
cd $SRC/cryptofuzz
LIBFUZZER_LINK="$LIB_FUZZING_ENGINE_DEPRECATED" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include" make -B -j$(nproc)

# Generate dictionary
./generate_dict

# Copy fuzzer
cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-boringssl-noasm
# Copy dictionary
cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-boringssl-noasm.dict
# Copy seed corpus
cp $SRC/cryptofuzz-corpora/boringssl_latest.zip $OUT/cryptofuzz-boringssl-noasm_seed_corpus.zip
