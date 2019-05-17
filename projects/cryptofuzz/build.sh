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

export LINK_FLAGS=""
export INCLUDE_PATH_FLAGS=""

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
    # Compile cryptopp (with assembly)
    cd $SRC/cryptopp
    make -j$(nproc)

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CRYPTOPP"
    export LIBCRYPTOPP_A_PATH="$SRC/cryptopp/libcryptopp.a"
    export CRYPTOPP_INCLUDE_PATH="$SRC/cryptopp"

    # Compile Cryptofuzz cryptopp (with assembly) module
    cd $SRC/cryptofuzz/modules/cryptopp
    make -B
fi

##############################################################################
if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile libgpg-error (dependency of libgcrypt)
    cd $SRC/
    tar jxvf libgpg-error-1.36.tar.bz2
    cd libgpg-error-1.36/
    ./configure --enable-static
    make -j$(nproc)
    make install
    export LINK_FLAGS="$LINK_FLAGS $SRC/libgpg-error-1.36/src/.libs/libgpg-error.a"

    # Compile libgcrypt (with assembly)
    cd $SRC/libgcrypt
    autoreconf -ivf
    ./configure --enable-static --disable-doc
    make -j$(nproc)

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBGCRYPT"
    export LIBGCRYPT_A_PATH="$SRC/libgcrypt/src/.libs/libgcrypt.a"
    export LIBGCRYPT_INCLUDE_PATH="$SRC/libgcrypt/src"

    # Compile Cryptofuzz libgcrypt (with assembly) module
    cd $SRC/cryptofuzz/modules/libgcrypt
    make -B
fi

##############################################################################
if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile libsodium (with assembly)
    cd $SRC/libsodium
    autoreconf -ivf
    ./configure
    make -j$(nproc)

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBSODIUM"
    export LIBSODIUM_A_PATH="$SRC/libsodium/src/libsodium/.libs/libsodium.a"
    export LIBSODIUM_INCLUDE_PATH="$SRC/libsodium/src/libsodium/include"

    # Compile Cryptofuzz libsodium (with assembly) module
    cd $SRC/cryptofuzz/modules/libsodium
    make -B
fi

if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile EverCrypt (with assembly)
    cd $SRC/
    tar zxvf evercrypt-v0.1alpha1.tar.gz
    mv hacl-star-evercrypt-v0.1alpha1 evercrypt

    cd $SRC/evercrypt/dist/generic
    make -j$(nproc) || true

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_EVERCRYPT"
    export EVERCRYPT_A_PATH="$SRC/evercrypt/dist/generic/libevercrypt.a"
    export KREMLIN_A_PATH="$SRC/evercrypt/dist/kremlin/kremlib/dist/minimal/*.o"
    export EVERCRYPT_INCLUDE_PATH="$SRC/evercrypt/dist"
    export KREMLIN_INCLUDE_PATH="$SRC/evercrypt/dist/kremlin/include"
    export INCLUDE_PATH_FLAGS="$INCLUDE_PATH_FLAGS -I $EVERCRYPT_INCLUDE_PATH -I $KREMLIN_INCLUDE_PATH"

    # Compile Cryptofuzz EverCrypt (with assembly) module
    cd $SRC/cryptofuzz/modules/evercrypt
    make -B
fi

##############################################################################
# Compile Cryptofuzz reference (without assembly) module
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_REFERENCE"
cd $SRC/cryptofuzz/modules/reference
make -B

##############################################################################
# Compile Cryptofuzz Veracrypt (without assembly) module
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_VERACRYPT"
cd $SRC/cryptofuzz/modules/veracrypt
make -B

##############################################################################
# Compile Cryptofuzz Monero (without assembly) module
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MONERO"
cd $SRC/cryptofuzz/modules/monero
make -B

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
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/libressl/include -DCRYPTOFUZZ_LIBRESSL $INCLUDE_PATH_FLAGS" make -B -j$(nproc)

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
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include $INCLUDE_PATH_FLAGS" make -B -j$(nproc)

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
LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include $INCLUDE_PATH_FLAGS" make -B -j$(nproc)

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
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include $INCLUDE_PATH_FLAGS" make -B -j$(nproc)

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
LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include $INCLUDE_PATH_FLAGS" make -B -j$(nproc)

# Generate dictionary
./generate_dict

# Copy fuzzer
cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-boringssl-noasm
# Copy dictionary
cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-boringssl-noasm.dict
# Copy seed corpus
cp $SRC/cryptofuzz-corpora/boringssl_latest.zip $OUT/cryptofuzz-boringssl-noasm_seed_corpus.zip
