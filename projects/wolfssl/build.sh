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

if true
then
    cd $SRC/wolfsm/
    ./install.sh

    cd $SRC/wolfssl/
    WOLFCRYPT_CONFIGURE_PARAMS="--enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-cryptocb --enable-eccencrypt --enable-aesgcm-stream --enable-smallstack --enable-ed25519-stream --enable-ed448-stream --enable-aesgcm-stream --enable-shake128 --enable-siphash --enable-eccsi --with-eccminsz=0 --enable-sm2 --enable-sm3 --enable-sm4-cbc --enable-sm4-ccm --enable-sm4-ctr --enable-sm4-ecb --enable-sm4-gcm"
    if [[ $CFLAGS = *sanitize=memory* ]]
    then
        WOLFCRYPT_CONFIGURE_PARAMS="$WOLFCRYPT_CONFIGURE_PARAMS --disable-asm"
    fi

    # Install Boost headers
    cd $SRC/
    tar jxf boost_1_82_0.tar.bz2
    cd boost_1_82_0/
    CFLAGS="" CXXFLAGS="" ./bootstrap.sh
    CFLAGS="" CXXFLAGS="" ./b2 headers
    cp -R boost/ /usr/include/

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
    echo -n 'ECC_Point_Dbl,' >>extra_options.h
    echo -n 'ECDH_Derive,' >>extra_options.h
    echo -n 'ECCSI_Sign,' >>extra_options.h
    echo -n 'ECCSI_Verify ' >>extra_options.h
    echo -n '"' >>extra_options.h

    # Build normal math fuzzer
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-normal-math/
    cp -R $SRC/wolfssl/ $SRC/wolfssl-normal-math/
    cd $SRC/wolfssl-normal-math/
    autoreconf -ivf
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP"
    if [[ $CFLAGS != *-m32* ]]
    then
        ./configure $WOLFCRYPT_CONFIGURE_PARAMS
    else
        # Compiling instrumented 32 bit normal math with asm is currently
        # not possible because it results in Clang error messages such as:
        #
        # wolfcrypt/src/tfm.c:3154:11: error: inline assembly requires more registers than available
        ./configure $WOLFCRYPT_CONFIGURE_PARAMS --disable-asm
    fi
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-normal-math/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-normal-math/"
    cd $SRC/cryptofuzz-normal-math/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-normal-math/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-normal-math
    CFLAGS="$OLD_CFLAGS"
    CXXFLAGS="$OLD_CXXFLAGS"
    unset WOLFCRYPT_LIBWOLFSSL_A_PATH
    unset WOLFCRYPT_INCLUDE_PATH

    # Build sp-math-all fuzzer
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-sp-math-all/
    cp -R $SRC/wolfssl/ $SRC/wolfssl-sp-math-all/
    cd $SRC/wolfssl-sp-math-all/
    autoreconf -ivf
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DWOLFSSL_SP_INT_NEGATIVE"
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

    # Build sp-math-all 8bit fuzzer
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-sp-math-all-8bit/
    cp -R $SRC/wolfssl/ $SRC/wolfssl-sp-math-all-8bit/
    cd $SRC/wolfssl-sp-math-all-8bit/
    autoreconf -ivf
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DSP_WORD_SIZE=8 -DWOLFSSL_SP_INT_NEGATIVE"
    ./configure $WOLFCRYPT_CONFIGURE_PARAMS --enable-sp-math-all
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-sp-math-all-8bit/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-sp-math-all-8bit/"
    cd $SRC/cryptofuzz-sp-math-all-8bit/modules/wolfcrypt
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
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DWOLFSSL_PUBLIC_ECC_ADD_DBL"
    # SP math does not support custom curves, so remove that flag
    export WOLFCRYPT_CONFIGURE_PARAMS_SP_MATH=${WOLFCRYPT_CONFIGURE_PARAMS//"--enable-ecccustcurves"/}
    if [[ $CFLAGS = *-m32* ]]
    then
        setarch i386 ./configure $WOLFCRYPT_CONFIGURE_PARAMS_SP_MATH --enable-sp --enable-sp-math
    elif [[ $CFLAGS = *sanitize=memory* ]]
    then
        ./configure $WOLFCRYPT_CONFIGURE_PARAMS_SP_MATH --enable-sp --enable-sp-math --disable-sp-asm
    else
        ./configure $WOLFCRYPT_CONFIGURE_PARAMS_SP_MATH --enable-sp --enable-sp-math
    fi
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-sp-math/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-sp-math/"
    cd $SRC/cryptofuzz-sp-math/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-sp-math/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-sp-math
    CFLAGS="$OLD_CFLAGS"
    CXXFLAGS="$OLD_CXXFLAGS"
    unset WOLFCRYPT_LIBWOLFSSL_A_PATH
    unset WOLFCRYPT_INCLUDE_PATH

    # Build fastmath fuzzer
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-fastmath/
    cp -R $SRC/wolfssl/ $SRC/wolfssl-fastmath/
    cd $SRC/wolfssl-fastmath/
    autoreconf -ivf
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP"
    ./configure $WOLFCRYPT_CONFIGURE_PARAMS --enable-fastmath
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-fastmath/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-fastmath/"
    cd $SRC/cryptofuzz-fastmath/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-fastmath/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-fastmath
    CFLAGS="$OLD_CFLAGS"
    CXXFLAGS="$OLD_CXXFLAGS"
    unset WOLFCRYPT_LIBWOLFSSL_A_PATH
    unset WOLFCRYPT_INCLUDE_PATH

    # Build heapmath fuzzer
    cp -R $SRC/cryptofuzz/ $SRC/cryptofuzz-heapmath/
    cp -R $SRC/wolfssl/ $SRC/wolfssl-heapmath/
    cd $SRC/wolfssl-heapmath/
    autoreconf -ivf
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP"
    ./configure $WOLFCRYPT_CONFIGURE_PARAMS --enable-heapmath
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-heapmath/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-heapmath/"
    cd $SRC/cryptofuzz-heapmath/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-heapmath/
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc)
    cp cryptofuzz $OUT/cryptofuzz-heapmath
    CFLAGS="$OLD_CFLAGS"
    CXXFLAGS="$OLD_CXXFLAGS"
    unset WOLFCRYPT_LIBWOLFSSL_A_PATH
    unset WOLFCRYPT_INCLUDE_PATH

    mkdir $SRC/cryptofuzz-seed-corpus/

    # Convert Wycheproof test vectors to Cryptofuzz corpus format
    find $SRC/wycheproof/testvectors/ -type f -name 'ecdsa_*' -exec $SRC/cryptofuzz-fastmath/cryptofuzz --from-wycheproof={},$SRC/cryptofuzz-seed-corpus/ \;
    find $SRC/wycheproof/testvectors/ -type f -name 'ecdh_*' -exec $SRC/cryptofuzz-fastmath/cryptofuzz --from-wycheproof={},$SRC/cryptofuzz-seed-corpus/ \;

    # Unpack corpora from other projects
    unzip -n $SRC/corpus_bearssl.zip -d $SRC/cryptofuzz_seed_corpus/ >/dev/null
    unzip -n $SRC/corpus_nettle.zip -d $SRC/cryptofuzz_seed_corpus/ >/dev/null
    unzip -n $SRC/corpus_libecc.zip -d $SRC/cryptofuzz_seed_corpus/ >/dev/null
    unzip -n $SRC/corpus_relic.zip -d $SRC/cryptofuzz_seed_corpus/ >/dev/null
    unzip -n $SRC/corpus_cryptofuzz-openssl.zip -d $SRC/cryptofuzz_seed_corpus/ >/dev/null
    unzip -n $SRC/corpus_cryptofuzz-boringssl.zip -d $SRC/cryptofuzz_seed_corpus/ >/dev/null
    unzip -n $SRC/corpus_cryptofuzz-nss.zip -d $SRC/cryptofuzz_seed_corpus/ >/dev/null

    # Import OpenSSL/LibreSSL corpora
    mkdir $SRC/openssl-expmod-corpus/
    unzip $SRC/corpus_openssl_expmod.zip -d $SRC/openssl-expmod-corpus/ >/dev/null
    find $SRC/openssl-expmod-corpus/ -type f -exec $SRC/cryptofuzz-fastmath/cryptofuzz --from-openssl-expmod={},$SRC/cryptofuzz-seed-corpus/ \;

    mkdir $SRC/libressl-expmod-corpus/
    unzip $SRC/corpus_libressl_expmod.zip -d $SRC/libressl-expmod-corpus/ >/dev/null
    find $SRC/libressl-expmod-corpus/ -type f -exec $SRC/cryptofuzz-fastmath/cryptofuzz --from-openssl-expmod={},$SRC/cryptofuzz-seed-corpus/ \;

    # Write Cryptofuzz built-in tests
    $SRC/cryptofuzz-fastmath/cryptofuzz --from-builtin-tests=$SRC/cryptofuzz-seed-corpus/

    # Pack it
    cd $SRC/cryptofuzz_seed_corpus
    zip -r $SRC/cryptofuzz_seed_corpus.zip . >/dev/null

    # Use it as the seed corpus for each Cryptofuzz-based fuzzer
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-normal-math_seed_corpus.zip
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-sp-math-all_seed_corpus.zip
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-sp-math-all-8bit_seed_corpus.zip
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-sp-math_seed_corpus.zip
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-fastmath_seed_corpus.zip
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-heapmath_seed_corpus.zip

    # Remove files that are no longer needed to prevent running out of disk space
    rm -rf $SRC/openssl-expmod-corpus/
    rm -rf $SRC/libressl-expmod-corpus/
    rm -rf $SRC/cryptofuzz_seed_corpus/
    rm -rf $SRC/cryptofuzz_seed_corpus.zip

    # Build SSL/SSH fuzzers
    NEW_SRC=$SRC/wolf-ssl-ssh-fuzzers/oss-fuzz/projects/wolf-ssl-ssh/
    cp -R $SRC/wolfssl/ $NEW_SRC
    cp -R $SRC/wolfssh/ $NEW_SRC
    cp -R $SRC/fuzzing-headers/ $NEW_SRC
    OSS_FUZZ_BUILD=1 SRC="$NEW_SRC" $NEW_SRC/build.sh

    # Copy corpora for SSL/SSH fuzzers
    cp $SRC/wolf-ssl-ssh-fuzzers/corpora/fuzzer-wolfssl-client-randomize_seed_corpus.zip $OUT/
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
