#!/bin/bash -eu
# Copyright 2022 Google LLC
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

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_CIRCL"
export LIBFUZZER_LINK="$LIB_FUZZING_ENGINE"
export LINK_FLAGS=""

# Install Boost headers
cd $SRC/
tar jxf boost_1_74_0.tar.bz2
cd boost_1_74_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
cp -R boost/ /usr/include/

# Configure Cryptofuzz
cd $SRC/cryptofuzz/
python gen_repository.py
echo -n '"' >>extra_options.h
echo -n "--force-module=circl " >>extra_options.h
echo -n "--curves=secp384r1,bls12_381 " >>extra_options.h
echo -n "--operations=" >>extra_options.h
echo -n "ECC_PrivateToPublic," >>extra_options.h
echo -n "ECC_Point_Add," >>extra_options.h
echo -n "ECC_Point_Mul," >>extra_options.h
echo -n "ECC_Point_Dbl," >>extra_options.h
echo -n "BLS_PrivateToPublic," >>extra_options.h
echo -n "BLS_G1_Add," >>extra_options.h
echo -n "BLS_G1_Mul," >>extra_options.h
echo -n "BLS_G1_Neg," >>extra_options.h
echo -n "BLS_G1_IsEq," >>extra_options.h
echo -n "BLS_IsG1OnCurve," >>extra_options.h
echo -n "BLS_HashToG1," >>extra_options.h
echo -n "BLS_PrivateToPublic_G2," >>extra_options.h
echo -n "BLS_G2_Add," >>extra_options.h
echo -n "BLS_G2_Mul," >>extra_options.h
echo -n "BLS_G2_Neg," >>extra_options.h
echo -n "BLS_G2_IsEq," >>extra_options.h
echo -n "BLS_IsG2OnCurve," >>extra_options.h
echo -n "BLS_HashToG2," >>extra_options.h
echo -n "BLS_Compress_G1," >>extra_options.h
echo -n "BLS_Decompress_G1," >>extra_options.h
echo -n "BLS_Pairing," >>extra_options.h
echo -n "BignumCalc_Mod_BLS12_381_P," >>extra_options.h
echo -n "BignumCalc_Mod_BLS12_381_R" >>extra_options.h
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
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOTAN -DCRYPTOFUZZ_BOTAN_IS_ORACLE"
export LIBBOTAN_A_PATH="$SRC/botan/libbotan-3.a"
export BOTAN_INCLUDE_PATH="$SRC/botan/build/include"
cd $SRC/cryptofuzz/modules/botan/
make -f Makefile-oracle -j $(nproc)

# Build blst
cd $SRC/blst/
./build.sh
export BLST_LIBBLST_A_PATH=$(realpath libblst.a)
export BLST_INCLUDE_PATH=$(realpath bindings/)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BLST"
cd $SRC/cryptofuzz/modules/blst/
make -j $(nproc)

cd $SRC/cryptofuzz/modules/circl/
make -j $(nproc)

cd $SRC/cryptofuzz/
make -j $(nproc)

cp cryptofuzz $OUT/

cp $SRC/cryptofuzz_seed_corpus.zip $OUT/
