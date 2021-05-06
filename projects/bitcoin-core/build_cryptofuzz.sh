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

# Prevent Boost compilation error with -std=c++17
export CXXFLAGS="$CXXFLAGS -D_LIBCPP_ENABLE_CXX17_REMOVED_AUTO_PTR"

# Build libsecp256k1
cd $SRC/secp256k1/
autoreconf -ivf
if [[ $CFLAGS = *sanitize=memory* ]]
then
    ./configure --enable-static --disable-tests --disable-benchmark --disable-exhaustive-tests --disable-valgrind --enable-module-recovery --enable-module-schnorrsig --enable-experimental --with-asm=no
else
    ./configure --enable-static --disable-tests --disable-benchmark --disable-exhaustive-tests --disable-valgrind --enable-module-recovery --enable-module-schnorrsig --enable-experimental
fi
make
export SECP256K1_INCLUDE_PATH=$(realpath include)
export LIBSECP256K1_A_PATH=$(realpath .libs/libsecp256k1.a)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SECP256K1"

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
echo -n '--operations=Digest,HMAC,KDF_HKDF,SymmetricEncrypt,SymmetricDecrypt,ECC_PrivateToPublic,ECC_ValidatePubkey,ECDSA_Sign,ECDSA_Verify,ECDSA_Recover,BignumCalc_Mod_2Exp256 ' >>extra_options.h
echo -n '--curves=secp256k1 ' >>extra_options.h
echo -n '--digests=NULL,SHA1,SHA256,SHA512,RIPEMD160,SHA3-256,SIPHASH64 ' >>extra_options.h
echo -n '--ciphers=CHACHA20,AES_256_CBC ' >>extra_options.h
echo -n '--calcops=Add,And,Div,IsEq,IsGt,IsGte,IsLt,IsLte,IsOdd,Mul,NumBits,Or,Set,Sub,Xor ' >>extra_options.h
echo -n '"' >>extra_options.h
cd modules/bitcoin/
make -B -j$(nproc)
cd ../secp256k1/
make -B -j$(nproc)
cd ../trezor/
make -B -j$(nproc)
cd ../botan/
make -B -j$(nproc)
cd ../../
make -B -j$(nproc)

cp cryptofuzz $OUT/cryptofuzz-bitcoin-cryptography

# Convert Wycheproof test vectors to Cryptofuzz corpus format
mkdir $SRC/corpus-cryptofuzz-wycheproof/
find $SRC/wycheproof/testvectors/ -type f -name 'ecdsa_secp256k1_*' -exec $SRC/cryptofuzz/cryptofuzz --from-wycheproof={},$SRC/corpus-cryptofuzz-wycheproof/ \;
# Pack it and use it as seed corpus
zip -j $OUT/cryptofuzz-bitcoin-cryptography_seed_corpus.zip $SRC/corpus-cryptofuzz-wycheproof/*
