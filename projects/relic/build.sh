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

# Build Relic
cd $SRC/relic/
mkdir build/
cd build/
if [[ $CFLAGS = *-m32* ]]
then
    export RELIC_ARCH="X86"
else
    export RELIC_ARCH="X64"
fi
cmake .. -DCOMP="$CFLAGS" -DQUIET=on -DRAND=CALL -DSHLIB=off -DSTBIN=off -DTESTS=0 -DBENCH=0 -DALLOC=DYNAMIC -DARCH=$RELIC_ARCH
make -j$(nproc)
cd ../..
export RELIC_PATH=$(realpath relic)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_RELIC"

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
echo -n '--force-module=relic ' >>extra_options.h
echo -n '--operations=BignumCalc,ECC_PrivateToPublic,ECC_ValidatePubkey,ECDSA_Sign,ECDSA_Verify,Digest,HMAC,KDF_X963,SymmetricEncrypt,SymmetricDecrypt,ECC_Point_Add,ECC_Point_Mul,ECC_Point_Dbl,ECC_Point_Neg ' >>extra_options.h
echo -n '--curves=secp256k1,secp256r1 ' >>extra_options.h
echo -n '--digests=NULL,SHA224,SHA256,SHA384,SHA512,BLAKE2S160,BLAKE2S256 ' >>extra_options.h
echo -n '--ciphers=AES_128_CBC,AES_192_CBC,AES_256_CBC ' >>extra_options.h
echo -n '--calcops=Abs,Add,Bit,ClearBit,Cmp,CmpAbs,Div,ExpMod,GCD,InvMod,IsEven,IsOdd,IsZero,Jacobi,LCM,LShift1,Mod,Mul,Neg,NumBits,RShift,SetBit,Sqr,Sqrt,Sub ' >>extra_options.h
echo -n '"' >>extra_options.h
cd modules/relic/
make -B -j$(nproc)
cd ../botan/
make -B -j$(nproc)
cd ../../
make -B -j$(nproc)

cp cryptofuzz $OUT/cryptofuzz-relic
