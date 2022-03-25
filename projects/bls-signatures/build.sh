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
tar jxf boost_1_74_0.tar.bz2
cd boost_1_74_0/
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
echo -n '"' >>extra_options.h


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
        # Patch to disable assembly
        touch new_no_asm.h
        echo "#if LIMB_T_BITS==32" >>new_no_asm.h
        echo "typedef unsigned long long llimb_t;" >>new_no_asm.h
        echo "#else" >>new_no_asm.h
        echo "typedef __uint128_t llimb_t;" >>new_no_asm.h
        echo "#endif" >>new_no_asm.h
        cat src/no_asm.h >>new_no_asm.h
        mv new_no_asm.h src/no_asm.h

        CFLAGS="$CFLAGS -D__BLST_NO_ASM__ -D__BLST_PORTABLE__" ./build.sh
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

# Build Chia
if [[ $CFLAGS != *sanitize=memory* && $CFLAGS != *-m32* ]]
then
    # Build and install libsodium
    cd $SRC/
    mkdir $SRC/libsodium-install
    tar zxf libsodium-1.0.18-stable.tar.gz
    cd $SRC/libsodium-stable/
    autoreconf -ivf
    ./configure --prefix="$SRC/libsodium-install/"
    make -j$(nproc)
    make install
    export CXXFLAGS="$CXXFLAGS -I $SRC/libsodium-install/include/"
    export LINK_FLAGS="$LINK_FLAGS $SRC/libsodium-install/lib/libsodium.a"

    cd $SRC/bls-signatures/
    mkdir build/
    cd build/
    if [[ $CFLAGS = *-m32* ]]
    then
        export CHIA_ARCH="X86"
    else
        export CHIA_ARCH="X64"
    fi
    cmake .. -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0 -DARCH=$CHIA_ARCH
    make -j$(nproc)
    export CHIA_BLS_LIBBLS_A_PATH=$(realpath src/libbls.a)
    export CHIA_BLS_LIBRELIC_S_A_PATH=$(realpath _deps/relic-build/lib/librelic_s.a)
    export CHIA_BLS_LIBSODIUM_A_PATH=$(realpath _deps/sodium-build/libsodium.a)
    export CHIA_BLS_INCLUDE_PATH=$(realpath ../src/)
    export CHIA_BLS_RELIC_INCLUDE_PATH_1=$(realpath _deps/relic-build/include/)
    export CHIA_BLS_RELIC_INCLUDE_PATH_2=$(realpath _deps/relic-src/include/)
    export LINK_FLAGS="$LINK_FLAGS -lgmp"
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CHIA_BLS"
fi

# Build mcl
if [[ "$SANITIZER" != "memory" ]]
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
    --disable-modules=locking_allocator,x509,tls \
    --build-targets=static \
    --without-documentation
else
    ./configure.py --cpu=x86_32 \
    --cc-bin=$CXX \
    --cc-abi-flags="$CXXFLAGS" \
    --disable-shared \
    --disable-modules=locking_allocator,x509,tls \
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
    cd $SRC/cryptofuzz/modules/chia_bls/
    make -B
fi

if [[ "$SANITIZER" != "memory" ]]
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
