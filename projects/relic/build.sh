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

# Prevent Boost compilation error with -std=c++17
export CXXFLAGS="$CXXFLAGS -D_LIBCPP_ENABLE_CXX17_REMOVED_AUTO_PTR"

# Build Relic
cd $SRC/relic/
mkdir build/
cd build/
cmake .. -DCOMP="$CFLAGS" -DQUIET=on -DRAND=CALL -DSHLIB=off -DSTBIN=off -DTESTS=0 -DBENCH=0
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

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOTAN"
export LIBBOTAN_A_PATH="$SRC/botan/libbotan-3.a"
export BOTAN_INCLUDE_PATH="$SRC/botan/build/include"

# Build Cryptofuzz
cd $SRC/cryptofuzz
python gen_repository.py
rm extra_options.h
echo -n '"' >>extra_options.h
echo -n '--force-module=relic ' >>extra_options.h
echo -n '--operations=BignumCalc,ECC_PrivateToPublic,ECDSA_Sign,ECDSA_Verify ' >>extra_options.h
echo -n '--curves=secp256k1,secp256r1 ' >>extra_options.h
echo -n '--digests=NULL ' >>extra_options.h
echo -n '"' >>extra_options.h
cd modules/relic/
make -B -j$(nproc)
cd ../botan/
make -B -j$(nproc)
cd ../../
make -B -j$(nproc)

cp cryptofuzz $OUT/cryptofuzz-relic
