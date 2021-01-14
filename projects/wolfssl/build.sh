#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

if [[ $CFLAGS != *sanitize=dataflow* ]]
then
    WOLFCRYPT_CONFIGURE_PARAMS="--enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-rabbit --enable-aesccm --enable-aesctr --enable-hc128 --enable-xts --enable-des3 --enable-idea --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-cryptocb --enable-eccencrypt"
    if [[ $CFLAGS = *sanitize=memory* ]]
    then
        WOLFCRYPT_CONFIGURE_PARAMS="$WOLFCRYPT_CONFIGURE_PARAMS --disable-asm"
    fi

    # Install Boost headers
    cd $SRC/
    tar jxf boost_1_74_0.tar.bz2
    cd boost_1_74_0/
    CFLAGS="" CXXFLAGS="" ./bootstrap.sh
    CFLAGS="" CXXFLAGS="" ./b2 headers
    cp -R boost/ /usr/include/

    OLD_CFLAGS="$CFLAGS"
    OLD_CXXFLAGS="$CXXFLAGS"

    # Configure Cryptofuzz
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-openssl-api/
    cd $SRC/cryptofuzz-openssl-api/
    python gen_repository.py
    rm extra_options.h
    echo -n '"' >>extra_options.h
    echo -n '--force-module=wolfCrypt-OpenSSL ' >>extra_options.h
    echo -n '"' >>extra_options.h

    # Build OpenSSL API fuzzer
    cp -R $SRC/wolfssl/ $SRC/wolfssl-openssl-api/
    cd $SRC/wolfssl-openssl-api/
    autoreconf -ivf
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP"
    if [[ $CFLAGS = *-m32* ]]
    then
        ./configure $WOLFCRYPT_CONFIGURE_PARAMS --enable-opensslall --enable-opensslextra --disable-fastmath
    else
        ./configure $WOLFCRYPT_CONFIGURE_PARAMS --enable-opensslall --enable-opensslextra
    fi
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT_OPENSSL"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-openssl-api/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-openssl-api/"
    cd $SRC/cryptofuzz-openssl-api/modules/wolfcrypt-openssl
    make -j$(nproc)
    cd $SRC/cryptofuzz-openssl-api/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-openssl-api
    CFLAGS="$OLD_CFLAGS"
    CXXFLAGS="$OLD_CXXFLAGS"
    unset WOLFCRYPT_LIBWOLFSSL_A_PATH
    unset WOLFCRYPT_INCLUDE_PATH

    # Configure Cryptofuzz
    cd $SRC/cryptofuzz/
    python gen_repository.py
    rm extra_options.h
    echo -n '"' >>extra_options.h
    echo -n '--force-module=wolfCrypt ' >>extra_options.h
    echo -n '--digests=NULL ' >>extra_options.h
    echo -n '--operations=BignumCalc,DH_GenerateKeyPair,DH_Derive,ECC_GenerateKeyPair,ECC_PrivateToPublic,ECC_ValidatePubkey,ECDSA_Verify,ECDSA_Sign' >>extra_options.h
    echo -n '"' >>extra_options.h

    # Build sp-math-all fuzzer
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-sp-math-all/
    cp -R $SRC/wolfssl/ $SRC/wolfssl-sp-math-all/
    cd $SRC/wolfssl-sp-math-all/
    autoreconf -ivf
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP"
    ./configure $WOLFCRYPT_CONFIGURE_PARAMS --enable-sp-math-all
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-sp-math-all/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-sp-math-all/"
    cd $SRC/cryptofuzz-sp-math-all/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-sp-math-all/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-sp-math-all
    CFLAGS="$OLD_CFLAGS"
    CXXFLAGS="$OLD_CXXFLAGS"
    unset WOLFCRYPT_LIBWOLFSSL_A_PATH
    unset WOLFCRYPT_INCLUDE_PATH

    # Build disable-fastmath fuzzer
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-disable-fastmath/
    cp -R $SRC/wolfssl/ $SRC/wolfssl-disable-fastmath/
    cd $SRC/wolfssl-disable-fastmath/
    autoreconf -ivf
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP"
    ./configure $WOLFCRYPT_CONFIGURE_PARAMS --disable-fastmath
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-disable-fastmath/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-disable-fastmath/"
    cd $SRC/cryptofuzz-disable-fastmath/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-disable-fastmath/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-disable-fastmath
    CFLAGS="$OLD_CFLAGS"
    CXXFLAGS="$OLD_CXXFLAGS"
    unset WOLFCRYPT_LIBWOLFSSL_A_PATH
    unset WOLFCRYPT_INCLUDE_PATH

    # Build SSL/SSH fuzzers
    NEW_SRC=$SRC/wolf-ssl-ssh-fuzzers/oss-fuzz/projects/wolf-ssl-ssh/
    cp -R $SRC/wolfssl/ $NEW_SRC
    cp -R $SRC/wolfssh/ $NEW_SRC
    cp -R $SRC/fuzzing-headers/ $NEW_SRC
    OSS_FUZZ_BUILD=1 SRC="$NEW_SRC" $NEW_SRC/build.sh
fi

if [[ $CFLAGS != *-m32* ]]
then
    cd $SRC/wolfssl

    # target_dir determined by Dockerfile
    target_dir="$SRC/fuzz-targets"

    # build wolfssl
    ./autogen.sh
    ./configure --enable-static --disable-shared --prefix=/usr CC="clang"
    make -j "$(nproc)" all
    make install

    # put linker arguments into the environment, appending to any existing ones
    export LDFLAGS="${LDFLAGS-""}"
    export LDLIBS="${LDLIBS-""} -lwolfssl $LIB_FUZZING_ENGINE"

    # make and export targets to $OUT; environment overridding internal variables
    cd "${target_dir}"
    make -e all
    make -e export prefix="$OUT"
fi
