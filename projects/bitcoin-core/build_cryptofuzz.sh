#!/bin/bash -eu
# Copyright 2021 Google LLC
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

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL"
export LIBFUZZER_LINK="$LIB_FUZZING_ENGINE"

# Install Boost headers
cd $SRC/
tar jxf boost_1_74_0.tar.bz2
cd boost_1_74_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
export CXXFLAGS="$CXXFLAGS -I $SRC/boost_1_74_0/"

# Preconfigure libsecp256k1
cd $SRC/secp256k1/
autoreconf -ivf
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SECP256K1"

function build_libsecp256k1() {
    # Build libsecp256k1
    cd $SRC/secp256k1/

    if test -f "Makefile"; then
        # Remove old configuration if it exists
        make clean

        # Prevent the error:
        # "configuration mismatch, invalid ECMULT_WINDOW_SIZE. Try deleting ecmult_static_pre_g.h before the build."
        rm -f src/ecmult_static_pre_g.h
    fi

    SECP256K1_CONFIGURE_PARAMS="
        --enable-static
        --disable-tests
        --disable-benchmark
        --disable-exhaustive-tests
        --enable-module-recovery
        --enable-experimental
        --enable-module-schnorrsig
        --enable-module-ecdh"

    if [[ $CFLAGS = *sanitize=memory* ]]
    then
        ./configure $SECP256K1_CONFIGURE_PARAMS --with-asm=no "$@"
    else
        ./configure $SECP256K1_CONFIGURE_PARAMS "$@"
    fi
    make

    export SECP256K1_INCLUDE_PATH=$(realpath .)
    export LIBSECP256K1_A_PATH=$(realpath .libs/libsecp256k1.a)

    # Build libsecp256k1 Cryptofuzz module
    cd $SRC/cryptofuzz/modules/secp256k1/
    make -B -j$(nproc)
}

# Build Trezor firmware
cd $SRC/trezor-firmware/crypto/
# Rename blake2b_* functions to avoid symbol collisions with other libraries
sed -i "s/\<blake2b_\([A-Za-z_]\)/trezor_blake2b_\1/g" *.c *.h
sed -i 's/\<blake2b(/trezor_blake2b(/g' *.c *.h
cd ../../
export TREZOR_FIRMWARE_PATH=$(realpath trezor-firmware)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_TREZOR_FIRMWARE"

# Build Botan
cd $SRC/botan
if [[ $CFLAGS != *-m32* ]]
then
    ./configure.py --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator --build-targets=static --without-documentation
else
    ./configure.py --cpu=x86_32 --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator --build-targets=static --without-documentation
fi
make -j$(nproc)

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOTAN -DCRYPTOFUZZ_BOTAN_IS_ORACLE"
export LIBBOTAN_A_PATH="$SRC/botan/libbotan-3.a"
export BOTAN_INCLUDE_PATH="$SRC/botan/build/include"

# Build Cryptofuzz
cd $SRC/cryptofuzz
python gen_repository.py
rm extra_options.h
echo -n '"' >>extra_options.h
echo -n '--operations=' >>extra_options.h
echo -n 'Digest,' >>extra_options.h
echo -n 'HMAC,' >>extra_options.h
echo -n 'KDF_HKDF,' >>extra_options.h
echo -n 'SymmetricEncrypt,' >>extra_options.h
echo -n 'SymmetricDecrypt,' >>extra_options.h
echo -n 'ECC_PrivateToPublic,' >>extra_options.h
echo -n 'ECC_ValidatePubkey,' >>extra_options.h
echo -n 'ECC_Point_Add,' >>extra_options.h
echo -n 'ECC_Point_Mul,' >>extra_options.h
echo -n 'ECDSA_Sign,' >>extra_options.h
echo -n 'ECDSA_Verify,' >>extra_options.h
echo -n 'ECDSA_Recover,' >>extra_options.h
echo -n 'Schnorr_Sign,' >>extra_options.h
echo -n 'Schnorr_Verify,' >>extra_options.h
echo -n 'ECDH_Derive,' >>extra_options.h
echo -n 'BignumCalc_Mod_2Exp256 ' >>extra_options.h
echo -n 'BignumCalc_Mod_SECP256K1 ' >>extra_options.h
echo -n '--curves=secp256k1 ' >>extra_options.h
echo -n '--digests=NULL,SHA1,SHA256,SHA512,RIPEMD160,SHA3-256,SIPHASH64 ' >>extra_options.h
echo -n '--ciphers=CHACHA20,AES_256_CBC ' >>extra_options.h
echo -n '--calcops=' >>extra_options.h
# Bitcoin Core arith_uint256.cpp operations
echo -n 'Add,And,Div,IsEq,IsGt,IsGte,IsLt,IsLte,IsOdd,Mul,NumBits,Or,Set,Sub,Xor,' >>extra_options.h
# libsecp256k1 scalar operations
echo -n 'IsZero,IsOne,IsEven,Add,Mul,InvMod,IsEq,CondSet,Bit,Set,RShift ' >>extra_options.h
echo -n '"' >>extra_options.h
cd modules/bitcoin/
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BITCOIN"
make -B -j$(nproc)
cd ../trezor/
make -B -j$(nproc)
cd ../botan/
make -B -j$(nproc)

# schnorr_fun is currently disabled because it was causing build failures
# See: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=39612
#cd ../schnorr_fun/
#export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SCHNORR_FUN"
#if [[ $CFLAGS != *-m32* ]]
#then
#    make
#else
#    make -f Makefile.i386
#fi

cd ../../

# Build with 3 configurations of libsecp256k1
# Discussion: https://github.com/google/oss-fuzz/pull/5717#issuecomment-842765383

build_libsecp256k1 "--with-ecmult-window=2" "--with-ecmult-gen-precision=2"
cd $SRC/cryptofuzz/
make -B -j$(nproc)
cp cryptofuzz $OUT/cryptofuzz-bitcoin-cryptography-w2-p2

build_libsecp256k1 "--with-ecmult-window=15" "--with-ecmult-gen-precision=4"
cd $SRC/cryptofuzz/
rm cryptofuzz
make
cp cryptofuzz $OUT/cryptofuzz-bitcoin-cryptography-w15-p4

# If the window size is larger than 15, this file must be deleted before proceeding
rm $SRC/secp256k1/src/precomputed_ecmult.c
build_libsecp256k1 "--with-ecmult-window=20" "--with-ecmult-gen-precision=8"
cd $SRC/cryptofuzz/
rm cryptofuzz
make
cp cryptofuzz $OUT/cryptofuzz-bitcoin-cryptography-w20-p8

# Convert Wycheproof test vectors to Cryptofuzz corpus format
mkdir $SRC/corpus-cryptofuzz-wycheproof/
find $SRC/wycheproof/testvectors/ -type f -name 'ecdsa_secp256k1_*' -exec $SRC/cryptofuzz/cryptofuzz --from-wycheproof={},$SRC/corpus-cryptofuzz-wycheproof/ \;
# Pack the Wycheproof test vectors
zip -j cryptofuzz-bitcoin-cryptography_seed_corpus.zip $SRC/corpus-cryptofuzz-wycheproof/*
# Use them as the seed corpus for each of the fuzzers
cp cryptofuzz-bitcoin-cryptography_seed_corpus.zip $OUT/cryptofuzz-bitcoin-cryptography-w2-p2_seed_corpus.zip
cp cryptofuzz-bitcoin-cryptography_seed_corpus.zip $OUT/cryptofuzz-bitcoin-cryptography-w15-p4_seed_corpus.zip
cp cryptofuzz-bitcoin-cryptography_seed_corpus.zip $OUT/cryptofuzz-bitcoin-cryptography-w20-p8_seed_corpus.zip
