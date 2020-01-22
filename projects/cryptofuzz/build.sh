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

if [[ $CFLAGS = *-m32* ]]
then
    export GOARCH=386
    export CGO_ENABLED=1
fi

export GO111MODULE=off
cd $SRC/go/src
./make.bash
export GOROOT=$(realpath $SRC/go)
export GOPATH=$GOROOT/packages
mkdir $GOPATH
export PATH=$GOROOT/bin:$PATH
export PATH=$GOROOT/packages/bin:$PATH

apt-get remove golang-1.9-go -y
rm /usr/bin/go

go get golang.org/x/crypto/blake2b
go get golang.org/x/crypto/blake2s
go get golang.org/x/crypto/md4
go get golang.org/x/crypto/ripemd160

# This enables runtime checks for C++-specific undefined behaviour.
export CXXFLAGS="$CXXFLAGS -D_GLIBCXX_DEBUG"

# Prevent Boost compilation error with -std=c++17
export CXXFLAGS="$CXXFLAGS -D_LIBCPP_ENABLE_CXX17_REMOVED_AUTO_PTR"

export CXXFLAGS="$CXXFLAGS -I $SRC/cryptofuzz/fuzzing-headers/include"
if [[ $CFLAGS = *sanitize=memory* ]]
then
    export CXXFLAGS="$CXXFLAGS -DMSAN"
fi

# Compile NSS
if [[ $CFLAGS != *-m32* ]]
then
    mkdir $SRC/nss-nspr
    mv $SRC/nss $SRC/nss-nspr/
    mv $SRC/nspr $SRC/nss-nspr/
    cd $SRC/nss-nspr/
    if [[ $CFLAGS = *sanitize=address* ]]
    then
        CFLAGS="" CXXFLAGS="" nss/build.sh --asan --static
    elif [[ $CFLAGS = *sanitize=memory* ]]
    then
        CFLAGS="" CXXFLAGS="" nss/build.sh --msan --static
    else
        CFLAGS="" CXXFLAGS="" nss/build.sh --ubsan --static
    fi
    export NSS_NSPR_PATH=$(realpath $SRC/nss-nspr/)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NSS"
    export LINK_FLAGS="$LINK_FLAGS -lsqlite3"

    # Compile Cryptofuzz NSS module
    cd $SRC/cryptofuzz/modules/nss
    make -B
fi

# Compile Cityhash
cd $SRC/cityhash
if [[ $CFLAGS != *-m32* ]]
then
    CXXFLAGS="$CXXFLAGS -msse4.2" ./configure --disable-shared >/dev/null 2>&1
else
    ./configure --disable-shared >/dev/null 2>&1
fi
make -j$(nproc) >/dev/null 2>&1

export CXXFLAGS="$CXXFLAGS -I$SRC/cityhash/src"
export CRYPTOFUZZ_REFERENCE_CITY_O_PATH="$SRC/cityhash/src/city.o"

##############################################################################
if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile cryptopp (with assembly)
    cd $SRC/cryptopp
    make -j$(nproc) >/dev/null 2>&1

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CRYPTOPP"
    export LIBCRYPTOPP_A_PATH="$SRC/cryptopp/libcryptopp.a"
    export CRYPTOPP_INCLUDE_PATH="$SRC/cryptopp"

    # Compile Cryptofuzz cryptopp (with assembly) module
    cd $SRC/cryptofuzz/modules/cryptopp
    make -B
fi

##############################################################################
# Compile mbed crypto
cd $SRC/mbed-crypto/
scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
if [[ $CFLAGS == *sanitize=memory* ]]
then
    scripts/config.pl unset MBEDTLS_HAVE_ASM
    scripts/config.pl unset MBEDTLS_PADLOCK_C
    scripts/config.pl unset MBEDTLS_AESNI_C
fi
mkdir build/
cd build/
cmake .. -DENABLE_PROGRAMS=0 -DENABLE_TESTING=0
make -j$(nproc) >/dev/null 2>&1
export MBEDTLS_LIBMBEDCRYPTO_A_PATH="$SRC/mbed-crypto/build/library/libmbedcrypto.a"
export MBEDTLS_INCLUDE_PATH="$SRC/mbed-crypto/include"
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MBEDTLS"
# Compile Cryptofuzz mbed crypto module
cd $SRC/cryptofuzz/modules/mbedtls
make -B

##############################################################################
# Compile Botan
cd $SRC/botan
if [[ $CFLAGS != *-m32* ]]
then
    ./configure.py --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator
else
    ./configure.py --cpu=x86_32 --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator
fi
make -j$(nproc)

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOTAN"
export LIBBOTAN_A_PATH="$SRC/botan/libbotan-2.a"
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
    make -j$(nproc) >/dev/null 2>&1
    make install
    export LINK_FLAGS="$LINK_FLAGS $SRC/libgpg-error-1.36/src/.libs/libgpg-error.a"

    # Compile libgcrypt (with assembly)
    cd $SRC/libgcrypt
    autoreconf -ivf
    if [[ $CFLAGS != *-m32* ]]
    then
        ./configure --enable-static --disable-doc
    else
        ./configure --enable-static --disable-doc --host=i386
    fi
    make -j$(nproc) >/dev/null 2>&1

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBGCRYPT"
    export LIBGCRYPT_A_PATH="$SRC/libgcrypt/src/.libs/libgcrypt.a"
    export LIBGCRYPT_INCLUDE_PATH="$SRC/libgcrypt/src"

    # Compile Cryptofuzz libgcrypt (with assembly) module
    cd $SRC/cryptofuzz/modules/libgcrypt
    make -B
fi

##############################################################################
# libsodium is currently disabled due to crashes whose cause
# is not entirely clear.
# It will be enabled again once the problem has been resolved.
# See also: https://github.com/jedisct1/libsodium/issues/859
#
#if [[ $CFLAGS != *sanitize=memory* ]]
#then
#    # Compile libsodium (with assembly)
#    cd $SRC/libsodium
#    autoreconf -ivf
#    ./configure
#    make -j$(nproc) >/dev/null 2>&1
#
#    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBSODIUM"
#    export LIBSODIUM_A_PATH="$SRC/libsodium/src/libsodium/.libs/libsodium.a"
#    export LIBSODIUM_INCLUDE_PATH="$SRC/libsodium/src/libsodium/include"
#
#    # Compile Cryptofuzz libsodium (with assembly) module
#    cd $SRC/cryptofuzz/modules/libsodium
#    make -B
#fi

if [[ $CFLAGS != *sanitize=memory* && $CFLAGS != *-m32* ]]
then
    # Compile EverCrypt (with assembly)
    cd $SRC/evercrypt/dist
    make -C portable -j$(nproc) libevercrypt.a >/dev/null 2>&1
    make -C kremlin/kremlib/dist/minimal -j$(nproc) >/dev/null 2>&1

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

##############################################################################
# Compile wolfCrypt
cd $SRC/wolfssl
autoreconf -ivf

export WOLFCRYPT_CONFIGURE_PARAMS="--enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-rabbit --enable-aesccm --enable-aesctr --enable-hc128 --enable-xts --enable-des3 --enable-idea --enable-x963kdf --enable-harden"

if [[ $CFLAGS = *sanitize=memory* ]]
then
    export WOLFCRYPT_CONFIGURE_PARAMS="$WOLFCRYPT_CONFIGURE_PARAMS -disable-asm"
fi

if [[ $CFLAGS = *-m32* ]]
then
    export WOLFCRYPT_CONFIGURE_PARAMS="$WOLFCRYPT_CONFIGURE_PARAMS -disable-fastmath"
fi

./configure $WOLFCRYPT_CONFIGURE_PARAMS
make -j$(nproc) >/dev/null 2>&1

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WOLFCRYPT"
export WOLFCRYPT_LIBWOLFSSL_A_PATH="$SRC/wolfssl/src/.libs/libwolfssl.a"
export WOLFCRYPT_INCLUDE_PATH="$SRC/wolfssl"

# Compile Cryptofuzz wolfcrypt (without assembly) module
cd $SRC/cryptofuzz/modules/wolfcrypt
make -B


##############################################################################
if [[ $CFLAGS != *sanitize=memory* && $CFLAGS != *-m32* ]]
then
    # Compile LibreSSL (with assembly)
    cd $SRC/libressl
    rm -rf build ; mkdir build
    cd build
    cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" ..
    make -j$(nproc) crypto >/dev/null 2>&1

    # Compile Cryptofuzz LibreSSL (with assembly) module
    cd $SRC/cryptofuzz/modules/openssl
    OPENSSL_INCLUDE_PATH="$SRC/libressl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/libressl/build/crypto/libcrypto.a" CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBRESSL" make -B

    # Compile Cryptofuzz
    cd $SRC/cryptofuzz
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/libressl/include -DCRYPTOFUZZ_LIBRESSL $INCLUDE_PATH_FLAGS" make -B -j$(nproc) >/dev/null 2>&1

    # Generate dictionary
    ./generate_dict

    # Copy fuzzer
    cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-libressl
    # Copy dictionary
    cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-libressl.dict
    # Copy seed corpus
    cp $SRC/cryptofuzz-corpora/libressl_latest.zip $OUT/cryptofuzz-libressl_seed_corpus.zip
fi

if [[ $CFLAGS != *-m32* ]]
then
    # Compile LibreSSL (without assembly)
    cd $SRC/libressl
    rm -rf build ; mkdir build
    cd build
    cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" -DENABLE_ASM=OFF ..
    make -j$(nproc) crypto >/dev/null 2>&1

    # Compile Cryptofuzz LibreSSL (without assembly) module
    cd $SRC/cryptofuzz/modules/openssl
    OPENSSL_INCLUDE_PATH="$SRC/libressl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/libressl/build/crypto/libcrypto.a" CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBRESSL" make -B

    # Compile Cryptofuzz
    cd $SRC/cryptofuzz
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/libressl/include -DCRYPTOFUZZ_LIBRESSL $INCLUDE_PATH_FLAGS" make -B -j$(nproc) >/dev/null 2>&1

    # Generate dictionary
    ./generate_dict

    # Copy fuzzer
    cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-libressl-noasm
    # Copy dictionary
    cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-libressl-noasm.dict
    # Copy seed corpus
    cp $SRC/cryptofuzz-corpora/libressl_latest.zip $OUT/cryptofuzz-libressl-noasm_seed_corpus.zip
fi

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
    make -j$(nproc) >/dev/null 2>&1

    # Compile Cryptofuzz OpenSSL (with assembly) module
    cd $SRC/cryptofuzz/modules/openssl
    OPENSSL_INCLUDE_PATH="$SRC/openssl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/openssl/libcrypto.a" make -B

    # Compile Cryptofuzz
    cd $SRC/cryptofuzz
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include $INCLUDE_PATH_FLAGS" make -B -j$(nproc) >/dev/null 2>&1

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
make -j$(nproc) >/dev/null 2>&1

# Compile Cryptofuzz OpenSSL (without assembly) module
cd $SRC/cryptofuzz/modules/openssl
OPENSSL_INCLUDE_PATH="$SRC/openssl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/openssl/libcrypto.a" make -B

# Compile Cryptofuzz
cd $SRC/cryptofuzz
LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include $INCLUDE_PATH_FLAGS" make -B -j$(nproc) >/dev/null 2>&1

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
if [[ $CFLAGS != *sanitize=memory* && $CFLAGS != *-m32* ]]
then
    # Compile BoringSSL (with assembly)
    cd $SRC/boringssl
    rm -rf build ; mkdir build
    cd build
    cmake -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" -DBORINGSSL_ALLOW_CXX_RUNTIME=1 ..
    make -j$(nproc) crypto >/dev/null 2>&1

    # Compile Cryptofuzz BoringSSL (with assembly) module
    cd $SRC/cryptofuzz/modules/openssl
    OPENSSL_INCLUDE_PATH="$SRC/boringssl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/boringssl/build/crypto/libcrypto.a" CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BORINGSSL" make -B

    # Compile Cryptofuzz
    cd $SRC/cryptofuzz
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include $INCLUDE_PATH_FLAGS" make -B -j$(nproc) >/dev/null 2>&1

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
make -j$(nproc) crypto >/dev/null 2>&1

# Compile Cryptofuzz BoringSSL (with assembly) module
cd $SRC/cryptofuzz/modules/openssl
OPENSSL_INCLUDE_PATH="$SRC/boringssl/include" OPENSSL_LIBCRYPTO_A_PATH="$SRC/boringssl/build/crypto/libcrypto.a" CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BORINGSSL" make -B

# Compile Cryptofuzz
cd $SRC/cryptofuzz
LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" CXXFLAGS="$CXXFLAGS -I $SRC/openssl/include $INCLUDE_PATH_FLAGS" make -B -j$(nproc) >/dev/null 2>&1

# Generate dictionary
./generate_dict

# Copy fuzzer
cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-boringssl-noasm
# Copy dictionary
cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-boringssl-noasm.dict
# Copy seed corpus
cp $SRC/cryptofuzz-corpora/boringssl_latest.zip $OUT/cryptofuzz-boringssl-noasm_seed_corpus.zip
