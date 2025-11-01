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

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -D_LIBCPP_DEBUG=1"
if [[ "$SANITIZER" = "memory" ]]
then
    export CXXFLAGS="$CXXFLAGS -DMSAN"
fi
export LIBFUZZER_LINK="$LIB_FUZZING_ENGINE"
export LINK_FLAGS=""

# Install Boost headers
cd $SRC/
tar jxf boost_1_84_0.tar.bz2
cd boost_1_84_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
cp -R boost/ /usr/include/

# Configure Cryptofuzz
cd $SRC/cryptofuzz/
python gen_repository.py
rm extra_options.h
echo -n '"' >>extra_options.h
echo -n "--force-module=blst " >>extra_options.h
echo -n "--operations=" >>extra_options.h
echo -n "BignumCalc," >>extra_options.h
echo -n "BignumCalc_Fp2," >>extra_options.h
echo -n "BignumCalc_Fp12," >>extra_options.h
echo -n "BLS_BatchVerify," >>extra_options.h
echo -n "BLS_FinalExp," >>extra_options.h
echo -n "BLS_GenerateKeyPair," >>extra_options.h
echo -n "BLS_HashToG1," >>extra_options.h
echo -n "BLS_HashToG2," >>extra_options.h
echo -n "BLS_IsG1OnCurve," >>extra_options.h
echo -n "BLS_IsG2OnCurve," >>extra_options.h
echo -n "BLS_Pairing," >>extra_options.h
echo -n "BLS_PrivateToPublic," >>extra_options.h
echo -n "BLS_PrivateToPublic_G2," >>extra_options.h
echo -n "BLS_Sign," >>extra_options.h
echo -n "BLS_Verify," >>extra_options.h
echo -n "BLS_Compress_G1," >>extra_options.h
echo -n "BLS_Compress_G2," >>extra_options.h
echo -n "BLS_Decompress_G1," >>extra_options.h
echo -n "BLS_Decompress_G2," >>extra_options.h
echo -n "BLS_G1_Add," >>extra_options.h
echo -n "BLS_G1_Mul," >>extra_options.h
echo -n "BLS_G1_IsEq," >>extra_options.h
echo -n "BLS_G1_Neg," >>extra_options.h
echo -n "BLS_G2_Add," >>extra_options.h
echo -n "BLS_G2_Mul," >>extra_options.h
echo -n "BLS_G2_IsEq," >>extra_options.h
echo -n "BLS_G2_Neg," >>extra_options.h
echo -n "BLS_Aggregate_G1", >>extra_options.h
echo -n "BLS_Aggregate_G2", >>extra_options.h
echo -n "BLS_MapToG1", >>extra_options.h
echo -n "BLS_MapToG2", >>extra_options.h
echo -n "BignumCalc_Mod_BLS12_381_P," >>extra_options.h
echo -n "BignumCalc_Mod_BLS12_381_R," >>extra_options.h
echo -n "KDF_HKDF," >>extra_options.h
echo -n "Misc " >>extra_options.h
echo -n "--digests=SHA256 " >>extra_options.h
echo -n "--curves=BLS12_381 " >>extra_options.h
echo -n '"' >>extra_options.h

# Build arkworks-algebra
if [[ "$SANITIZER" != "memory" ]]
then
    cd $SRC/cryptofuzz/modules/arkworks-algebra/
    if [[ $CFLAGS != *-m32* ]]
    then
        make
    else
        rustup target add i686-unknown-linux-gnu
        make -f Makefile-i386
    fi
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_ARKWORKS_ALGEBRA"
fi

# Build Constantine
if [[ "$SANITIZER" != "memory" ]]
then
    cd $SRC/
    if [[ $CFLAGS != *-m32* ]]
    then
        tar Jxf nim-2.0.8-linux_x64.tar.xz
    else
        tar Jxf nim-2.0.8-linux_x32.tar.xz
    fi
    export NIM_PATH=$(realpath nim-2.0.8)

    export CONSTANTINE_PATH=$SRC/constantine/

    cd $SRC/cryptofuzz/modules/constantine/
    if [[ $CFLAGS != *-m32* ]]
    then
        make
    else
        make -f Makefile-i386
    fi

    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CONSTANTINE"
fi

if [[ $CFLAGS = *-m32* ]]
then
    # Build and install libgmp
    cd $SRC/
    mkdir $SRC/libgmp-install
    tar xf gmp-6.2.1.tar.lz
    cd $SRC/gmp-6.2.1/
    autoreconf -ivf
    if [[ $CFLAGS != *-m32* ]]
    then
        ./configure --prefix="$SRC/libgmp-install/" --enable-cxx
    else
        setarch i386 ./configure --prefix="$SRC/libgmp-install/" --enable-cxx
    fi
    make -j$(nproc)
    make install
    export CXXFLAGS="$CXXFLAGS -I $SRC/libgmp-install/include/"
fi

function build_blst() {
    if [[ "$SANITIZER" == "memory" ]]
    then
        CFLAGS="$CFLAGS -D__BLST_NO_ASM__ -D__BLST_PORTABLE__ -Dllimb_t=__uint128_t -D__builtin_assume(x)=(void)(x)" ./build.sh
    else
        ./build.sh
    fi

    export BLST_LIBBLST_A_PATH=$(realpath libblst.a)
    export BLST_INCLUDE_PATH=$(realpath bindings/)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BLST"
}

# Build blst (normal)
cp -R $SRC/blst/ $SRC/blst_normal/
cd $SRC/blst_normal/
build_blst

# Build mcl
if [[ "$SANITIZER" != "memory" && $CFLAGS != *-m32* ]]
then
    cd $SRC/mcl/
    mkdir build/
    cd build/
    if [[ $CFLAGS != *-m32* ]]
    then
        cmake .. -DMCL_STATIC_LIB=on
        export LINK_FLAGS="$LINK_FLAGS -lgmp"
    else
        cmake .. -DMCL_STATIC_LIB=on \
        -DGMP_INCLUDE_DIR="$SRC/libgmp-install/include/" \
        -DGMP_LIBRARY="$SRC/libgmp-install/lib/libgmp.a" \
        -DGMP_GMPXX_INCLUDE_DIR="$SRC/libgmp-install/include/" \
        -DGMP_GMPXX_LIBRARY="$SRC/libgmp-install/lib/libgmpxx.a" \
        -DMCL_USE_ASM=off
        export LINK_FLAGS="$LINK_FLAGS $SRC/libgmp-install/lib/libgmp.a"
    fi
    make
    export MCL_INCLUDE_PATH=$(realpath ../include/)
    export MCL_LIBMCL_A_PATH=$(realpath lib/libmcl.a)
    export MCL_LIBMCLBN384_A_PATH=$(realpath lib/libmclbn384.a)
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MCL"
fi

# Build Botan
cd $SRC/botan/
if [[ $CFLAGS != *-m32* ]]
then
    ./configure.py --cc-bin=$CXX \
    --cc-abi-flags="$CXXFLAGS" \
    --disable-shared \
    --disable-modules=locking_allocator,x509 \
    --build-targets=static \
    --without-documentation
else
    ./configure.py --cpu=x86_32 \
    --cc-bin=$CXX \
    --cc-abi-flags="$CXXFLAGS" \
    --disable-shared \
    --disable-modules=locking_allocator,x509 \
    --build-targets=static \
    --without-documentation
fi
make -j$(nproc)

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOTAN -DCRYPTOFUZZ_BOTAN_IS_ORACLE"
export LIBBOTAN_A_PATH="$SRC/botan/libbotan-3.a"
export BOTAN_INCLUDE_PATH="$SRC/botan/build/include"

# Build modules
cd $SRC/cryptofuzz/modules/botan/
make -B

cd $SRC/cryptofuzz/modules/blst/
make -B

if [[ $CFLAGS != *sanitize=memory* && $CFLAGS != *-m32* ]]
then
    cd $SRC/cryptofuzz/modules/mcl/
    make -B
fi

# Build Cryptofuzz
cd $SRC/cryptofuzz/
make -B -j

cp cryptofuzz $OUT/cryptofuzz-bls-signatures

# Build blst (optimized for size)
cp -R $SRC/blst/ $SRC/blst_optimize_size/
cd $SRC/blst_optimize_size/
export CFLAGS="$CFLAGS -D__OPTIMIZE_SIZE__"
build_blst

cd $SRC/cryptofuzz/modules/blst/
make -B

# Build Cryptofuzz
cd $SRC/cryptofuzz/
rm entry.o; make

cp cryptofuzz $OUT/cryptofuzz-bls-signatures_optimize_size
