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
export LINK_FLAGS=""

# Compile xxd
$CC $SRC/xxd.c -o /usr/bin/xxd

# Install Boost headers
cd $SRC/
tar jxf boost_1_74_0.tar.bz2
cd boost_1_74_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
cp -R boost/ /usr/include/

# Generate lookup tables. This only needs to be done once.
cd $SRC/cryptofuzz
python gen_repository.py

# Build libff
cd $SRC/libff/
mkdir build/
cd build/
cmake -DCURVE=ALT_BN128 ..
make -j$(nproc)
export LIBFF_A_PATH=$(realpath libff/libff.a)
export LIBFF_INCLUDE_PATH=$(realpath ..)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBFF"
export LINK_FLAGS="$LINK_FLAGS -lgmp"

# Build libff Cryptofuzz module
cd $SRC/cryptofuzz/modules/libff/
make -f Makefile-alt_bn128

# Build Skale solidity
cp $SRC/cryptofuzz/modules/skalesolidity/Cryptofuzz.sol $SRC/skale-manager/contracts/
cd $SRC/skale-manager/
yarn
export SKALE_CRYPTOFUZZ_SOL_JSON=$(realpath artifacts/contracts/Cryptofuzz.sol/Cryptofuzz.json)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SKALE_SOLIDITY"

# Build Skale solidity Cryptofuzz module
cd $SRC/cryptofuzz/modules/skalesolidity/
export GO111MODULE=off
go get ./... || true
make

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

# Build Botan Cryptofuzz module
cd $SRC/cryptofuzz/modules/botan/
make -f Makefile-oracle

# Build Cryptofuzz
cd $SRC/cryptofuzz
rm extra_options.h
echo -n '"' >>extra_options.h
echo -n '--force-module=SkaleSolidity ' >>extra_options.h
echo -n '--operations=BLS_IsG1OnCurve,BLS_IsG2OnCurve,BLS_G1_Add,BLS_G1_Mul,BLS_G1_Neg,BLS_G2_IsEq,BLS_G2_Add,BLS_G2_Mul,BLS_G2_Neg,BignumCalc,BignumCalc_Fp2 ' >>extra_options.h
echo -n '--calcops=GCD,ExpMod,MulDiv,Sqrt,Add,Sub,Mul,InvMod,Sqr,IsEQ ' >>extra_options.h
echo -n '"' >>extra_options.h
make -j$(nproc)
cp cryptofuzz $OUT/skale-solidity-fuzzer