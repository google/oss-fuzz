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
cp -R boost/ /usr/include/

# Build libecc
cd $SRC/libecc
python3 scripts/expand_libecc.py --name="secp112r2" --prime=0xdb7c2abf62e35e668076bead208b --order=0x36df0aafd8b8d7597ca10520d04b --a=0x6127c24c05f38a0aaaf65c0ef02c --b=0x51def1815db5ed74fcc34c85d709 --gx=0x4ba30ab5e892b4e1649dd0928643 --gy=0xadcd46f5882e3747def36e956e97 --cofactor=4
python3 scripts/expand_libecc.py --name="secp128r2" --prime=0xfffffffdffffffffffffffffffffffff --order=0x3fffffff7fffffffbe0024720613b5a3 --a=0xd6031998d1b3bbfebf59cc9bbff9aee1 --b=0x5eeefca380d02919dc2c6558bb6d8a5d --gx=0x7b6aa5d85e572983e6fb32a7cdebc140 --gy=0x27b6916a894d3aee7106fe805fc34b44 --cofactor=4
export CFLAGS="$CFLAGS -DUSE_CRYPTOFUZZ"
make -j$(nproc) build/libsign.a
export LIBECC_PATH=$(realpath .)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBECC"

# Build Botan
cd $SRC/botan
if [[ $CFLAGS != *-m32* ]]
then
    ./configure.py --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator,x509 --build-targets=static --without-documentation
else
    ./configure.py --cpu=x86_32 --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator,x509 --build-targets=static --without-documentation
fi
make -j$(nproc)

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOTAN -DCRYPTOFUZZ_BOTAN_IS_ORACLE"
export LIBBOTAN_A_PATH="$SRC/botan/libbotan-3.a"
export BOTAN_INCLUDE_PATH="$SRC/botan/build/include"

# Compile libgmp
cd $SRC/
tar --lzip -xvf gmp-6.2.1.tar.lz
cd $SRC/gmp-6.2.1/
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

cd $SRC/wolfssl/
# Checkout at commit that's known to be bug-free
git checkout a96983e6d38e8d093892dd9e5d58b72753bac3ac

# Install support for wolfCrypt SM algorithms
cd $SRC/wolfsm/
./install.sh

# Compile wolfSSL
cd $SRC/wolfssl/
# Note (to self):
# Compiling wolfCrypt with SP math instead of normal math due to symbol collisions (specifically fp_* functions) between libecc and wolfCrypt otherwise.
export CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DWOLFSSL_SP_INT_NEGATIVE"
autoreconf -ivf
export WOLFCRYPT_CONFIGURE_PARAMS="--enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-cryptocb --enable-eccencrypt --enable-smallstack --enable-ed25519-stream --enable-ed448-stream --enable-sp-math-all --enable-aesgcm-stream --enable-shake128 --enable-siphash --enable-sm2 --enable-sm3"
if [[ $CFLAGS = *sanitize=memory* ]]
then
    export WOLFCRYPT_CONFIGURE_PARAMS="$WOLFCRYPT_CONFIGURE_PARAMS -disable-asm"
fi
./configure $WOLFCRYPT_CONFIGURE_PARAMS
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WOLFCRYPT"
export WOLFCRYPT_LIBWOLFSSL_A_PATH=`realpath src/.libs/libwolfssl.a`
export WOLFCRYPT_INCLUDE_PATH=`realpath .`

# Build Cryptofuzz
cd $SRC/cryptofuzz
python gen_repository.py
rm extra_options.h
echo -n '"' >>extra_options.h
echo -n '--force-module=libecc ' >>extra_options.h
echo -n '--operations=Digest,HMAC,ECC_PrivateToPublic,ECC_ValidatePubkey,ECDSA_Sign,ECDSA_Verify,ECGDSA_Sign,ECGDSA_Verify,ECRDSA_Sign,ECRDSA_Verify,ECDH_Derive,ECC_Point_Add,ECC_Point_Mul,ECC_Point_Dbl,ECC_Point_Neg,BignumCalc ' >>extra_options.h
echo -n '--curves=brainpool192r1,brainpool192t1,brainpool224r1,brainpool224t1,brainpool256r1,brainpool256t1,brainpool320r1,brainpool320t1,brainpool384r1,brainpool384t1,brainpool512r1,brainpool512t1,secp112r2,secp128r2,secp192r1,secp192k1,secp224r1,secp224k1,secp256r1,secp256k1,secp384r1,secp521r1,frp256v1,secp256k1,sm2p256v1,gost_256A,gost_512A,gostr3410_2001_cryptopro_a,gostr3410_2001_cryptopro_b,gostr3410_2001_cryptopro_c,gostr3410_2001_cryptopro_xcha,gostr3410_2001_cryptopro_xchb,gostr3410_2001_test,tc26_gost_3410_12_256_a,tc26_gost_3410_12_256_b,tc26_gost_3410_12_256_c,tc26_gost_3410_12_256_d,tc26_gost_3410_12_512_a,tc26_gost_3410_12_512_b,tc26_gost_3410_12_512_c,tc26_gost_3410_12_512_test ' >>extra_options.h
echo -n '--digests=NULL,SHA224,SHA256,SHA3-224,SHA3-256,SHA3-384,SHA3-512,SHA384,SHA512,SHA512-224,SHA512-256,SM3,SHAKE256_114,STREEBOG-256,STREEBOG-512,RIPEMD160,BASH224,BASH256,BASH384,BASH512 ' >>extra_options.h
echo -n '--calcops=Add,AddMod,And,Bit,Cmp,CondAdd,CondSub,Div,ExpMod,ExtGCD_X,ExtGCD_Y,GCD,InvMod,IsOdd,IsOne,IsZero,LRot,LShift1,Mod,Mul,MulMod,NegMod,NumBits,One,Or,RRot,RShift,RandMod,Sqr,Sub,SubMod,Xor,Zero ' >>extra_options.h
echo -n '"' >>extra_options.h
cd modules/libecc/
make -B -j$(nproc)
cd ../botan/
make -B -j$(nproc)
cd ../libgmp/
make -B -j$(nproc)
cd ../wolfcrypt/
make -B -j$(nproc)
cd ../../
make -B -j$(nproc)

cp cryptofuzz $OUT/cryptofuzz-libecc
