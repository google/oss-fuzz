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
    WOLFCRYPT_CONFIGURE_PARAMS="--enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-cryptocb --enable-eccencrypt --enable-aesgcm-stream --enable-smallstack --enable-ed25519-stream --enable-ed448-stream"
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
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT -DCRYPTOFUZZ_BOTAN"
    export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl-normal-math/src/.libs/libwolfssl.a"
    export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl-normal-math/"
    cd $SRC/cryptofuzz-normal-math/modules/wolfcrypt
    make -j$(nproc)
    cd $SRC/cryptofuzz-normal-math/modules/botan
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
    CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DWOLFSSL_PUBLIC_ECC_ADD_DBL"
    ./configure $WOLFCRYPT_CONFIGURE_PARAMS --enable-sp --enable-sp-math
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

    mkdir $SRC/cryptofuzz-seed-corpus/

    # Convert Wycheproof test vectors to Cryptofuzz corpus format
    find $SRC/wycheproof/testvectors/ -type f -name 'ecdsa_*' -exec $SRC/cryptofuzz-disable-fastmath/cryptofuzz --from-wycheproof={},$SRC/cryptofuzz-seed-corpus/ \;
    find $SRC/wycheproof/testvectors/ -type f -name 'ecdh_*' -exec $SRC/cryptofuzz-disable-fastmath/cryptofuzz --from-wycheproof={},$SRC/cryptofuzz-seed-corpus/ \;

    # Unpack corpora from other projects
    unzip -n $SRC/corpus_bearssl.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_nettle.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_libecc.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_relic.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_cryptofuzz-openssl.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_cryptofuzz-boringssl.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_cryptofuzz-nss.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_bitcoin-core-w2-p2.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_bitcoin-core-w15-p4.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_bitcoin-core-w20-p8.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_num-bigint.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_wolfssl_sp-math-all.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_wolfssl_sp-math-all-8bit.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_wolfssl_sp-math.zip -d $SRC/cryptofuzz_seed_corpus/
    unzip -n $SRC/corpus_wolfssl_disable-fastmath.zip -d $SRC/cryptofuzz_seed_corpus/

    # Import Botan corpora
    mkdir $SRC/botan-p256-corpus/
    unzip $SRC/corpus_botan_ecc_p256.zip -d $SRC/botan-p256-corpus/
    find $SRC/botan-p256-corpus/ -type f -exec $SRC/cryptofuzz-disable-fastmath/cryptofuzz --from-botan={},$SRC/cryptofuzz-seed-corpus/,secp256r1 \;

    mkdir $SRC/botan-p384-corpus/
    unzip $SRC/corpus_botan_ecc_p384.zip -d $SRC/botan-p384-corpus/
    find $SRC/botan-p384-corpus/ -type f -exec $SRC/cryptofuzz-disable-fastmath/cryptofuzz --from-botan={},$SRC/cryptofuzz-seed-corpus/,secp384r1 \;

    mkdir $SRC/botan-p521-corpus/
    unzip $SRC/corpus_botan_ecc_p521.zip -d $SRC/botan-p521-corpus/
    find $SRC/botan-p521-corpus/ -type f -exec $SRC/cryptofuzz-disable-fastmath/cryptofuzz --from-botan={},$SRC/cryptofuzz-seed-corpus/,secp521r1 \;

    mkdir $SRC/botan-bp256-corpus/
    unzip $SRC/corpus_botan_ecc_bp256.zip -d $SRC/botan-bp256-corpus/
    find $SRC/botan-bp256-corpus/ -type f -exec $SRC/cryptofuzz-disable-fastmath/cryptofuzz --from-botan={},$SRC/cryptofuzz-seed-corpus/,brainpool256r1 \;

    # Import OpenSSL/LibreSSL corpora
    mkdir $SRC/openssl-expmod-corpus/
    unzip $SRC/corpus_openssl_expmod.zip -d $SRC/openssl-expmod-corpus/
    find $SRC/openssl-expmod-corpus/ -type f -exec $SRC/cryptofuzz-disable-fastmath/cryptofuzz --from-openssl-expmod={},$SRC/cryptofuzz-seed-corpus/ \;

    mkdir $SRC/libressl-expmod-corpus/
    unzip $SRC/corpus_libressl_expmod.zip -d $SRC/libressl-expmod-corpus/
    find $SRC/libressl-expmod-corpus/ -type f -exec $SRC/cryptofuzz-disable-fastmath/cryptofuzz --from-openssl-expmod={},$SRC/cryptofuzz-seed-corpus/ \;

    # Pack it
    cd $SRC/cryptofuzz_seed_corpus
    zip -r $SRC/cryptofuzz_seed_corpus.zip .

    # Use it as the seed corpus for each Cryptofuzz-based fuzzer
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-normal-math_seed_corpus.zip
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-sp-math-all_seed_corpus.zip
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-sp-math-all-8bit_seed_corpus.zip
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-sp-math_seed_corpus.zip
    cp $SRC/cryptofuzz_seed_corpus.zip $OUT/cryptofuzz-disable-fastmath_seed_corpus.zip

    # Remove files that are no longer needed to prevent running out of disk space
    rm -rf $SRC/botan-p256-corpus/
    rm -rf $SRC/botan-p384-corpus/
    rm -rf $SRC/botan-p521-corpus/
    rm -rf $SRC/botan-bp256-corpus/
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
