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

export GO111MODULE=off

if [[ $CFLAGS != *sanitize=memory* && $CFLAGS != *-m32* ]]
then
    # Install nodejs/npm
    # It is required for building noble-bls12-381
    cd $SRC/
    tar Jxf node-v14.17.1-linux-x64.tar.xz
    export PATH="$PATH:$SRC/node-v14.17.1-linux-x64/bin/"
fi

# Compile xxd
$CC $SRC/xxd.c -o /usr/bin/xxd

# Copy the upstream checkout of xxHash over the old version
rm -rf $SRC/cryptofuzz/modules/reference/xxHash/
cp -R $SRC/xxHash/ $SRC/cryptofuzz/modules/reference/

# Install Boost headers
cd $SRC/
tar jxf boost_1_74_0.tar.bz2
cd boost_1_74_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
cp -R boost/ /usr/include/

export LINK_FLAGS=""
export INCLUDE_PATH_FLAGS=""

# Generate lookup tables. This only needs to be done once.
cd $SRC/cryptofuzz
python gen_repository.py

git clone https://github.com/golang/crypto $GOPATH/src/golang.org/x/crypto
git clone https://github.com/golang/sys.git $GOPATH/src/golang.org/x/sys

# This enables runtime checks for C++-specific undefined behaviour.
export CXXFLAGS="$CXXFLAGS -D_GLIBCXX_DEBUG"

# wolfCrypt uses a slightly different ECDH algorithm than Trezor and libsecp256k1.
# This disables running ECDH in Trezor and libsecp256k1 to prevent mismatches.
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_DISABLE_SPECIAL_ECDH"

export CXXFLAGS="$CXXFLAGS -I $SRC/cryptofuzz/fuzzing-headers/include"
if [[ $CFLAGS = *sanitize=memory* ]]
then
    export CXXFLAGS="$CXXFLAGS -DMSAN"
fi

if [[ $CFLAGS != *sanitize=memory* && $CFLAGS != *-m32* ]]
then
    # Compile libfuzzer-js (required for all JavaScript libraries)
    export LIBFUZZER_A_PATH="$LIB_FUZZING_ENGINE"
    cd $SRC/libfuzzer-js/
    make
    export LIBFUZZER_JS_PATH=$(realpath .)
    export LINK_FLAGS="$LINK_FLAGS $LIBFUZZER_JS_PATH/js.o $LIBFUZZER_JS_PATH/quickjs/libquickjs.a"

    # Compile bn.js module
    export BN_JS_PATH="$SRC/bn.js/lib/bn.js"
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BN_JS"
    cd $SRC/cryptofuzz/modules/bn.js/
    make

    # Compile bignumber.js module
    export BIGNUMBER_JS_PATH="$SRC/bignumber.js/bignumber.js"
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BIGNUMBER_JS"
    cd $SRC/cryptofuzz/modules/bignumber.js/
    make

    export CRYPTO_JS_PATH="$SRC/crypto-js/"
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CRYPTO_JS"
    cd $SRC/cryptofuzz/modules/crypto-js/
    make
fi

# Compile NSS
if [[ $CFLAGS != *-m32* ]]
then
    mkdir $SRC/nss-nspr
    mv $SRC/nss $SRC/nss-nspr/
    mv $SRC/nspr $SRC/nss-nspr/
    cd $SRC/nss-nspr/

    # Prevent compilation error with Clang
    export CFLAGS="$CFLAGS -Wno-unused-but-set-variable"

    CXX="$CXX -stdlib=libc++" LDFLAGS="$CFLAGS" nss/build.sh --enable-fips --static --disable-tests --fuzz=oss

    export NSS_NSPR_PATH=$(realpath $SRC/nss-nspr/)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NSS"
    export LINK_FLAGS="$LINK_FLAGS -lsqlite3"

    # Compile Cryptofuzz NSS module
    cd $SRC/cryptofuzz/modules/nss
    make -B
fi

# Compile Monocypher
cd $SRC/Monocypher/
make CC="$CC" CFLAGS="$CFLAGS"
export LIBMONOCYPHER_A_PATH=$(realpath lib/libmonocypher.a)
export MONOCYPHER_INCLUDE_PATH=$(realpath src/)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MONOCYPHER"

# Compile Cryptofuzz monocypher module
cd $SRC/cryptofuzz/modules/monocypher
make -B

# Rename blake2b_* functions to avoid symbol collisions with other libraries
cd $SRC/trezor-firmware/crypto
sed -i "s/\<blake2b_\([A-Za-z_]\)/trezor_blake2b_\1/g" *.c *.h
sed -i 's/\<blake2b(/trezor_blake2b(/g' *.c *.h

# Compile Cryptofuzz trezor module
export TREZOR_FIRMWARE_PATH=$(realpath $SRC/trezor-firmware)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_TREZOR_FIRMWARE"
cd $SRC/cryptofuzz/modules/trezor
make -B

# Compile libtomcrypt
cd $SRC/libtomcrypt
if [[ $CFLAGS != *sanitize=memory* ]]
then
    make -j$(nproc)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBTOMCRYPT"
    export LIBTOMCRYPT_INCLUDE_PATH=$(realpath src/headers/)
    export LIBTOMCRYPT_A_PATH=$(realpath libtomcrypt.a)

    # Compile Cryptofuzz libtomcrypt module
    cd $SRC/cryptofuzz/modules/libtomcrypt
    make -B
fi

## Build blst
#cd $SRC/blst/
## Patch to disable assembly
## This is to prevent false positives, see:
## https://github.com/google/oss-fuzz/issues/5914
#touch new_no_asm.h
#echo "#if LIMB_T_BITS==32" >>new_no_asm.h
#echo "typedef unsigned long long llimb_t;" >>new_no_asm.h
#echo "#else" >>new_no_asm.h
#echo "typedef __uint128_t llimb_t;" >>new_no_asm.h
#echo "#endif" >>new_no_asm.h
#cat src/no_asm.h >>new_no_asm.h
#mv new_no_asm.h src/no_asm.h
#CFLAGS="$CFLAGS -D__BLST_NO_ASM__ -D__BLST_PORTABLE__" ./build.sh
#export BLST_LIBBLST_A_PATH=$(realpath libblst.a)
#export BLST_INCLUDE_PATH=$(realpath bindings/)
#export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BLST"
#
## Compile Cryptofuzz blst module
#cd $SRC/cryptofuzz/modules/blst/
#make -B -j$(nproc)

# Build libsecp256k1
cd $SRC/secp256k1/
autoreconf -ivf
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SECP256K1"
if [[ $CFLAGS = *sanitize=memory* ]]
then
    ./configure --enable-static --disable-tests --disable-benchmark --disable-exhaustive-tests --enable-module-recovery --enable-experimental --enable-module-schnorrsig --enable-module-ecdh --with-asm=no
else
    ./configure --enable-static --disable-tests --disable-benchmark --disable-exhaustive-tests --enable-module-recovery --enable-experimental --enable-module-schnorrsig --enable-module-ecdh
fi
make
export SECP256K1_INCLUDE_PATH=$(realpath .)
export LIBSECP256K1_A_PATH=$(realpath .libs/libsecp256k1.a)

# Compile Cryptofuzz libsecp256k1 module
cd $SRC/cryptofuzz/modules/secp256k1/
make -B -j$(nproc)

#if [[ $CFLAGS != *sanitize=memory* && $CFLAGS != *-m32* ]]
#then
# noble-secp256k1
#    cd $SRC/noble-secp256k1/
#    npm install && npm run build
#    export NOBLE_SECP256K1_PATH=$(realpath lib/index.js)
#
#    cd $SRC/cryptofuzz/modules/noble-secp256k1/
#    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NOBLE_SECP256K1"
#    make -B

# noble-bls12-381
#    cd $SRC/noble-bls12-381/
#    cp math.ts new_index.ts
#    $(awk '/^export/ {print "tail -n +"FNR+1" index.ts"; exit}' index.ts) >>new_index.ts
#    mv new_index.ts index.ts
#    npm install && npm run build
#    export NOBLE_BLS12_381_PATH=$(realpath index.js)
#    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NOBLE_BLS12_381"
#    cd $SRC/cryptofuzz/modules/noble-bls12-381/
#    make -B

# noble-ed25519
#    cd $SRC/cryptofuzz/modules/noble-ed25519/
#    export NOBLE_ED25519_PATH="$SRC/noble-ed25519/index.js"
#    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NOBLE_ED25519"
#    make -B
#fi

## Compile SymCrypt
cd $SRC/SymCrypt/
# Unittests don't build with clang and are not needed anyway
sed -i "s/^add_subdirectory(unittest)$//g" CMakeLists.txt

mkdir b/
cd b/
cmake ../
make symcrypt_common symcrypt_generic -j$(nproc)

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SYMCRYPT"
export SYMCRYPT_INCLUDE_PATH=$(realpath ../inc/)
export LIBSYMCRYPT_COMMON_A_PATH=$(realpath lib/x86_64/Generic/libsymcrypt_common.a)
export SYMCRYPT_GENERIC_A_PATH=$(realpath lib/x86_64/Generic/symcrypt_generic.a)

# Compile Cryptofuzz SymCrypt module
cd $SRC/cryptofuzz/modules/symcrypt
make -B

# Compile libgmp
cd $SRC/libgmp/
autoreconf -ivf
if [[ $CFLAGS = *-m32* ]]
then
    setarch i386 ./configure --enable-maintainer-mode --enable-assert
elif [[ $CFLAGS = *sanitize=memory* ]]
then
    ./configure --enable-maintainer-mode --enable-assert --disable-assembly
else
    ./configure --enable-maintainer-mode --enable-assert
fi
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBGMP"
export LIBGMP_INCLUDE_PATH=$(realpath .)
export LIBGMP_A_PATH=$(realpath .libs/libgmp.a)
# Compile Cryptofuzz libgmp module
cd $SRC/cryptofuzz/modules/libgmp
make -B

# Compile mpdecimal
cd $SRC/
tar zxf mpdecimal-2.5.1.tar.gz
cd mpdecimal-2.5.1/
./configure
cd libmpdec/
make libmpdec.a -j$(nproc)
cd ../
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MPDECIMAL"
export LIBMPDEC_A_PATH=$(realpath libmpdec/libmpdec.a)
export LIBMPDEC_INCLUDE_PATH=$(realpath libmpdec/)
# Compile Cryptofuzz mpdecimal module
cd $SRC/cryptofuzz/modules/mpdecimal
make -B

# Compile Cityhash
cd $SRC/cityhash
if [[ $CFLAGS != *-m32* ]]
then
    CXXFLAGS="$CXXFLAGS -msse4.2" ./configure --disable-shared
else
    ./configure --disable-shared
fi
make -j$(nproc)

export CXXFLAGS="$CXXFLAGS -I$SRC/cityhash/src"
export CRYPTOFUZZ_REFERENCE_CITY_O_PATH="$SRC/cityhash/src/city.o"

##############################################################################
# Compile cryptopp
cd $SRC/cryptopp
if [[ $CFLAGS != *sanitize=memory* ]]
then
    make libcryptopp.a -j$(nproc)
else
    export CXXFLAGS="$CXXFLAGS -DCRYPTOPP_DISABLE_ASM=1"
    make libcryptopp.a -j$(nproc)
fi

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CRYPTOPP"
export LIBCRYPTOPP_A_PATH="$SRC/cryptopp/libcryptopp.a"
export CRYPTOPP_INCLUDE_PATH="$SRC/cryptopp"

# Compile Cryptofuzz cryptopp module
cd $SRC/cryptofuzz/modules/cryptopp
make -B

##############################################################################
# Compile mbed TLS
cd $SRC/mbedtls/
scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
scripts/config.pl set MBEDTLS_CMAC_C
scripts/config.pl set MBEDTLS_NIST_KW_C
scripts/config.pl set MBEDTLS_ARIA_C
if [[ $CFLAGS == *sanitize=memory* ]]
then
    scripts/config.pl unset MBEDTLS_HAVE_ASM
    scripts/config.pl unset MBEDTLS_PADLOCK_C
    scripts/config.pl unset MBEDTLS_AESNI_C
fi
mkdir build/
cd build/
cmake .. -DENABLE_PROGRAMS=0 -DENABLE_TESTING=0
make -j$(nproc)
export MBEDTLS_LIBMBEDCRYPTO_A_PATH="$SRC/mbedtls/build/library/libmbedcrypto.a"
export MBEDTLS_INCLUDE_PATH="$SRC/mbedtls/include"
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MBEDTLS"
# Compile Cryptofuzz mbed crypto module
cd $SRC/cryptofuzz/modules/mbedtls
make -B

##############################################################################
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

##############################################################################
if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile libgpg-error (dependency of libgcrypt)
    cd $SRC/
    tar jxvf libgpg-error-1.36.tar.bz2
    cd libgpg-error-1.36/
    if [[ $CFLAGS != *-m32* ]]
    then
        ./configure --enable-static
    else
        ./configure --enable-static --host=i386
    fi
    make -j$(nproc)
    make install
    export LINK_FLAGS="$LINK_FLAGS $SRC/libgpg-error-1.36/src/.libs/libgpg-error.a"

    # Compile libgcrypt
    cd $SRC/libgcrypt
    autoreconf -ivf
    if [[ $CFLAGS = *-m32* ]]
    then
        ./configure --enable-static --disable-doc --host=i386
    else
        ./configure --enable-static --disable-doc
    fi
    make -j$(nproc)

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBGCRYPT"
    export LIBGCRYPT_A_PATH="$SRC/libgcrypt/src/.libs/libgcrypt.a"
    export LIBGCRYPT_INCLUDE_PATH="$SRC/libgcrypt/src"

    # Compile Cryptofuzz libgcrypt module
    cd $SRC/cryptofuzz/modules/libgcrypt
    make -B
fi

# Compile libsodium
cd $SRC/libsodium
autoreconf -ivf
if [[ $CFLAGS != *sanitize=memory* ]]
then
    ./configure
else
    ./configure --disable-asm
fi
make -j$(nproc)

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBSODIUM"
export LIBSODIUM_A_PATH="$SRC/libsodium/src/libsodium/.libs/libsodium.a"
export LIBSODIUM_INCLUDE_PATH="$SRC/libsodium/src/libsodium/include"

# Compile Cryptofuzz libsodium module
cd $SRC/cryptofuzz/modules/libsodium
make -B

if [[ $CFLAGS != *sanitize=memory* && $CFLAGS != *-m32* ]]
then
    # Compile EverCrypt (with assembly)
    cd $SRC/evercrypt/dist
    make -C portable -j$(nproc) libevercrypt.a
    make -C kremlin/kremlib/dist/minimal -j$(nproc)

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_EVERCRYPT"
    export EVERCRYPT_A_PATH="$SRC/evercrypt/dist/portable/libevercrypt.a"
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
# Compile Cryptofuzz Golang module
if [[ $CFLAGS != *sanitize=memory* ]]
then
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_GOLANG"
    cd $SRC/cryptofuzz/modules/golang
    make -B
fi

if [[ $CFLAGS != *-m32* ]]
then
    # Compile Cryptofuzz (NSS-based)
    cd $SRC/cryptofuzz
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL $INCLUDE_PATH_FLAGS" make -B -j$(nproc)

    # Generate dictionary
    ./generate_dict

    # Copy fuzzer
    cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-nss
    # Copy dictionary
    cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-nss.dict
    # Copy seed corpus
    cp $SRC/cryptofuzz-corpora/libressl_latest.zip $OUT/cryptofuzz-nss_seed_corpus.zip

    rm $SRC/cryptofuzz/modules/nss/module.a

    CXXFLAGS=${CXXFLAGS//"-DCRYPTOFUZZ_NSS"/}
    LINK_FLAGS=${LINK_FLAGS//"-lsqlite3"/}
fi

if [[ $CFLAGS != *sanitize=memory* ]]
then
    # libtomcrypt can only be compiled with NSS, because OpenSSL, LibreSSL and
    # BoringSSL have symbol collisions with libtomcrypt.
    #
    # So, now that NSS-based Cryptofuzz has been compiled, remove libtomcrypt
    export CXXFLAGS=${CXXFLAGS/-DCRYPTOFUZZ_LIBTOMCRYPT/}
    rm -rf "$LIBTOMCRYPT_A_PATH"
fi

##############################################################################
# Compile wolfCrypt
cd $SRC/wolfssl
# Enable additional wolfCrypt features which cannot be activated through arguments to ./configure
export CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP"
autoreconf -ivf

export WOLFCRYPT_CONFIGURE_PARAMS="--enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-hc128 --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-shake256 --enable-curve25519 --enable-curve448 --disable-crypttests --disable-examples --enable-keygen --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-cryptocb --enable-eccencrypt"

if [[ $CFLAGS = *sanitize=memory* ]]
then
    export WOLFCRYPT_CONFIGURE_PARAMS="$WOLFCRYPT_CONFIGURE_PARAMS -disable-asm"
fi

if [[ $CFLAGS = *-m32* ]]
then
    export WOLFCRYPT_CONFIGURE_PARAMS="$WOLFCRYPT_CONFIGURE_PARAMS -disable-fastmath"
fi

./configure $WOLFCRYPT_CONFIGURE_PARAMS
make -j$(nproc)

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WOLFCRYPT"
export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl/src/.libs/libwolfssl.a"
export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl"

# Compile Cryptofuzz wolfcrypt (without assembly) module
cd $SRC/cryptofuzz/modules/wolfcrypt
make -B

# OpenSSL can currently not be used together with wolfCrypt due to symbol collisions
export SAVE_CXXFLAGS="$CXXFLAGS"
export CXXFLAGS=${CXXFLAGS/-DCRYPTOFUZZ_WOLFCRYPT/}

##############################################################################
if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile Openssl (with assembly)
    cd $SRC/openssl
    if [[ $CFLAGS != *-m32* ]]
    then
        ./config --debug enable-md2 enable-rc5
    else
        setarch i386 ./config --debug enable-md2 enable-rc5
    fi
    make -j$(nproc)

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
if [[ $CFLAGS != *-m32* ]]
then
    ./config --debug no-asm enable-md2 enable-rc5
else
    setarch i386 ./config --debug no-asm enable-md2 enable-rc5
fi
make clean
make -j$(nproc)

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

export CXXFLAGS="$SAVE_CXXFLAGS"

##############################################################################
if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile BoringSSL (with assembly)
    cd $SRC/boringssl
    rm -rf build ; mkdir build
    cd build
    if [[ $CFLAGS = *-m32* ]]
    then
        setarch i386 cmake -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" -DBORINGSSL_ALLOW_CXX_RUNTIME=1 -DCMAKE_ASM_FLAGS="-m32" ..
    else
        cmake -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" -DBORINGSSL_ALLOW_CXX_RUNTIME=1 ..
    fi
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
