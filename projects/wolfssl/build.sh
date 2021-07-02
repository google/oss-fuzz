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
    WOLFCRYPT_CONFIGURE_PARAMS="--enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-rabbit --enable-aesccm --enable-aesctr --enable-hc128 --enable-xts --enable-des3 --enable-idea --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-cryptocb --enable-eccencrypt --enable-aesgcm-stream --enable-smallstack"
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

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOTAN_IS_ORACLE"

    OLD_CFLAGS="$CFLAGS"
    OLD_CXXFLAGS="$CXXFLAGS"

    # Configure Cryptofuzz
    cd $SRC/cryptofuzz
    sed -i 's/kNegativeIntegers = false/kNegativeIntegers = true/g' config.h
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
    echo -n '--operations=' >>extra_options.h
    echo -n 'BignumCalc,' >>extra_options.h
    echo -n 'DH_GenerateKeyPair,' >>extra_options.h
    echo -n 'DH_Derive,' >>extra_options.h
    echo -n 'ECC_GenerateKeyPair,' >>extra_options.h
    echo -n 'ECC_PrivateToPublic,' >>extra_options.h
    echo -n 'ECC_ValidatePubkey,' >>extra_options.h
    echo -n 'ECDSA_Verify,' >>extra_options.h
    echo -n 'ECDSA_Sign,' >>extra_options.h
    echo -n 'ECIES_Encrypt,' >>extra_options.h
    echo -n 'ECIES_Decrypt,' >>extra_options.h
    echo -n 'ECC_Point_Add,' >>extra_options.h
    echo -n 'ECC_Point_Mul,' >>extra_options.h
    echo -n 'ECDH_Derive ' >>extra_options.h
    echo -n '"' >>extra_options.h

    # Build Botan
    cd $SRC/botan
    if [[ $CFLAGS != *-m32* ]]
    then
        ./configure.py --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator --build-targets=static --without-documentation
    else
        ./configure.py --cpu=x86_32 --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator --build-targets=static --without-documentation
    fi
    make -j$(nproc)
    export LIBBOTAN_A_PATH="$SRC/botan/libbotan-3.a"
    export BOTAN_INCLUDE_PATH="$SRC/botan/build/include"

    # Build sp-math-all fuzzer
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-sp-math-all/
    cp -R $SRC/wolfssl/ $SRC/wolfssl-sp-math-all/
    cd $SRC/wolfssl-sp-math-all/
    autoreconf -ivf
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DWOLFSSL_SP_INT_NEGATIVE"
    ./configure $WOLFCRYPT_CONFIGURE_PARAMS --enable-sp-math-all
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT -DCRYPTOFUZZ_BOTAN"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-sp-math-all/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-sp-math-all/"
    cd $SRC/cryptofuzz-sp-math-all/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-sp-math-all/modules/botan
    make -j$(nproc)
    cd $SRC/cryptofuzz-sp-math-all/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-sp-math-all
    CFLAGS="$OLD_CFLAGS"
    CXXFLAGS="$OLD_CXXFLAGS"
    unset WOLFCRYPT_LIBWOLFSSL_A_PATH
    unset WOLFCRYPT_INCLUDE_PATH

    # Build sp-math-all 8bit fuzzer
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-sp-math-all-8bit/
    cp -R $SRC/wolfssl/ $SRC/wolfssl-sp-math-all-8bit/
    cd $SRC/wolfssl-sp-math-all-8bit/
    autoreconf -ivf
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DSP_WORD_SIZE=8 -DWOLFSSL_SP_INT_NEGATIVE"
    ./configure $WOLFCRYPT_CONFIGURE_PARAMS --enable-sp-math-all
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT -DCRYPTOFUZZ_BOTAN"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-sp-math-all-8bit/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-sp-math-all-8bit/"
    cd $SRC/cryptofuzz-sp-math-all-8bit/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-sp-math-all-8bit/modules/botan
    make -j$(nproc)
    cd $SRC/cryptofuzz-sp-math-all-8bit/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-sp-math-all-8bit
    CFLAGS="$OLD_CFLAGS"
    CXXFLAGS="$OLD_CXXFLAGS"
    unset WOLFCRYPT_LIBWOLFSSL_A_PATH
    unset WOLFCRYPT_INCLUDE_PATH

    # Build sp-math fuzzer
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-sp-math/
    cp -R $SRC/wolfssl/ $SRC/wolfssl-sp-math/
    cd $SRC/wolfssl-sp-math/
    autoreconf -ivf
    # -DHAVE_ECC_BRAINPOOL and -DHAVE_ECC_KOBLITZ are lacking from the CFLAGS; these are not supported by SP math
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP"
    # SP math does not support custom curves, so remove that flag
    export WOLFCRYPT_CONFIGURE_PARAMS_SP_MATH=${WOLFCRYPT_CONFIGURE_PARAMS//"--enable-ecccustcurves"/}
    ./configure $WOLFCRYPT_CONFIGURE_PARAMS_SP_MATH --enable-sp --enable-sp-math
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT -DCRYPTOFUZZ_BOTAN"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-sp-math/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-sp-math/"
    cd $SRC/cryptofuzz-sp-math/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-sp-math/modules/botan
    make -j$(nproc)
    cd $SRC/cryptofuzz-sp-math/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-sp-math
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
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT -DCRYPTOFUZZ_BOTAN"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-disable-fastmath/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-disable-fastmath/"
    cd $SRC/cryptofuzz-disable-fastmath/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-disable-fastmath/modules/botan
    make -j$(nproc)
    cd $SRC/cryptofuzz-disable-fastmath/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-disable-fastmath
    CFLAGS="$OLD_CFLAGS"
    CXXFLAGS="$OLD_CXXFLAGS"
    unset WOLFCRYPT_LIBWOLFSSL_A_PATH
    unset WOLFCRYPT_INCLUDE_PATH

    # Convert Wycheproof test vectors to Cryptofuzz corpus format
    mkdir $SRC/corpus-cryptofuzz-wycheproof/
    find $SRC/wycheproof/testvectors/ -type f -name 'ecdsa_*' -exec $SRC/cryptofuzz-disable-fastmath/cryptofuzz --from-wycheproof={},$SRC/corpus-cryptofuzz-wycheproof/ \;
    # Pack it
    zip -j $SRC/cryptofuzz_wycheproof_seed_corpus.zip $SRC/corpus-cryptofuzz-wycheproof/*
    # Use it as the seed corpus for each Cryptofuzz-based fuzzer
    cp $SRC/cryptofuzz_wycheproof_seed_corpus.zip $OUT/cryptofuzz-sp-math-all_seed_corpus.zip
    cp $SRC/cryptofuzz_wycheproof_seed_corpus.zip $OUT/cryptofuzz-sp-math-all-8bit_seed_corpus.zip
    cp $SRC/cryptofuzz_wycheproof_seed_corpus.zip $OUT/cryptofuzz-sp-math_seed_corpus.zip
    cp $SRC/cryptofuzz_wycheproof_seed_corpus.zip $OUT/cryptofuzz-disable-fastmath_seed_corpus.zip

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
