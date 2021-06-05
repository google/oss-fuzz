#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# Not using OpenSSL
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL"

# Install Boost headers
    cd $SRC/
    tar jxf boost_1_74_0.tar.bz2
    cd boost_1_74_0/
    CFLAGS="" CXXFLAGS="" ./bootstrap.sh
    CFLAGS="" CXXFLAGS="" ./b2 headers
    cp -R boost/ /usr/include/

# Generate lookup tables. This only needs to be done once.
    cd $SRC/cryptofuzz
    python gen_repository.py

# Only test primitives which BearSSL supports
    rm extra_options.h
    echo -n '"' >>extra_options.h
    echo -n '--force-module=BearSSL ' >>extra_options.h
    echo -n '--digests=MD5,SHA1,SHA224,SHA256,SHA384,SHA512,MD5_SHA1,SHAKE128,SHAKE256 ' >>extra_options.h
    echo -n '--ciphers=AES_128_GCM,AES_192_GCM,AES_256_GCM,AES_128_CCM,AES_192_CCM,AES_256_CCM,CHACHA20,CHACHA20_POLY1305 ' >>extra_options.h
    echo -n '--operations=Digest,HMAC,SymmetricEncrypt,SymmetricDecrypt,KDF_HKDF,KDF_TLS1_PRF,ECC_GenerateKeyPair,ECC_PrivateToPublic,ECDSA_Verify,ECDSA_Sign' >>extra_options.h
    echo -n '"' >>extra_options.h

# Compile BearSSL
    cd $SRC/BearSSL/
    sed -i '/^CC = /d' conf/Unix.mk
    sed -i '/^CFLAGS = /d' conf/Unix.mk
    make -j$(nproc) lib

    export BEARSSL_INCLUDE_PATH=$(realpath inc/)
    export LIBBEARSSL_A_PATH=$(realpath ./build/libbearssl.a)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BEARSSL"

    # Compile Cryptofuzz BearSSL module
    cd $SRC/cryptofuzz/modules/bearssl
    make -B

# Compile Botan
    cd $SRC/botan
    if [[ $CFLAGS != *-m32* ]]
    then
        ./configure.py --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator --build-targets=static --without-documentation
    else
        ./configure.py --cpu=x86_32 --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator --build-targets=static --without-documentation
    fi
    make -j$(nproc)

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOTAN"
    export LIBBOTAN_A_PATH="$SRC/botan/libbotan-3.a"
    export BOTAN_INCLUDE_PATH="$SRC/botan/build/include"

    # Compile Cryptofuzz Botan module
    cd $SRC/cryptofuzz/modules/botan
    make -B

# Compile Cryptofuzz
    cd $SRC/cryptofuzz
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc) >/dev/null

    # Generate dictionary
    ./generate_dict

    # Copy fuzzer
    cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-bearssl
    # Copy dictionary
    cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-bearssl.dict
