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
git checkout cryptofuzz
export CFLAGS="$CFLAGS -DUSE_CRYPTOFUZZ"
make -j$(nproc) build/libsign.a
export LIBECC_PATH=$(realpath .)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBECC"

# Build Botan
cd $SRC/botan
if [[ $CFLAGS != *-m32* ]]
then
    ./configure.py --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator,x509,tls --build-targets=static --without-documentation
else
    ./configure.py --cpu=x86_32 --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator,x509,tls --build-targets=static --without-documentation
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
echo -n '--force-module=libecc ' >>extra_options.h
echo -n '--operations=Digest,HMAC,ECC_PrivateToPublic,ECDSA_Sign,ECDSA_Verify,ECGDSA_Sign,ECGDSA_Verify,ECRDSA_Sign,ECRDSA_Verify,ECC_Point_Add,ECC_Point_Mul,ECC_Point_Dbl,ECC_Point_Neg,BignumCalc ' >>extra_options.h
echo -n '--curves=brainpool224r1,brainpool256r1,brainpool384r1,brainpool512r1,secp192r1,secp224r1,secp256r1,secp384r1,secp521r1,secp256k1 ' >>extra_options.h
echo -n '--digests=NULL,SHA224,SHA256,SHA3-224,SHA3-256,SHA3-384,SHA3-512,SHA384,SHA512,SHA512-224,SHA512-256,SM3,SHAKE256_114,STREEBOG-256,STREEBOG-512 ' >>extra_options.h
echo -n '--calcops=Add,AddMod,And,Bit,GCD,InvMod,IsOdd,IsOne,IsZero,LShift1,Mod,Mul,MulMod,NumBits,Or,RShift,Sqr,Sub,SubMod,Xor,LRot,RRot ' >>extra_options.h
echo -n '"' >>extra_options.h
cd modules/libecc/
make -B -j$(nproc)
cd ../botan/
make -B -j$(nproc)
cd ../../
make -B -j$(nproc)

cp cryptofuzz $OUT/cryptofuzz-libecc
