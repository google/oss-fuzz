#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

export LINK_FLAGS=""

# Not using OpenSSL
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL"

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

if [[ $CFLAGS != *sanitize=memory* ]]
then
    # Compile libgmp
        cd $SRC/
        lzip -d gmp-6.2.1.tar.lz
        tar xf gmp-6.2.1.tar

        cd gmp-6.2.1/
        autoreconf -ivf
        if [[ $CFLAGS != *-m32* ]]
        then
            ./configure --enable-maintainer-mode
        else
            setarch i386 ./configure --enable-maintainer-mode
        fi
        make -j$(nproc)
        make install

    # Compile Nettle (with libgmp)
        mkdir $SRC/nettle-with-libgmp-install/
        cp -R $SRC/nettle $SRC/nettle-with-libgmp/
        cd $SRC/nettle-with-libgmp/
        bash .bootstrap
        export NETTLE_LIBDIR=`realpath ../nettle-with-libgmp-install`/lib
        if [[ $CFLAGS != *sanitize=memory* ]]
        then
            ./configure --disable-documentation --disable-openssl --prefix=`realpath ../nettle-with-libgmp-install` --libdir="$NETTLE_LIBDIR"
        else
            ./configure --disable-documentation --disable-openssl --disable-assembler --prefix=`realpath ../nettle-with-libgmp-install` --libdir="$NETTLE_LIBDIR"
        fi
        make -j$(nproc)
        make install

        export LIBNETTLE_A_PATH=$NETTLE_LIBDIR/libnettle.a
        export LIBHOGWEED_A_PATH=$NETTLE_LIBDIR/libhogweed.a
        export NETTLE_INCLUDE_PATH=`realpath ../nettle-with-libgmp-install/include`
        export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NETTLE"
        export LINK_FLAGS="$LINK_FLAGS /usr/local/lib/libgmp.a"

        # Compile Cryptofuzz Nettle module
        cd $SRC/cryptofuzz/modules/nettle
        make -f Makefile-hogweed -B

    ##############################################################################
    # Compile Botan
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

        # Compile Cryptofuzz Botan module
        cd $SRC/cryptofuzz/modules/botan
        make -B

    # Compile Cryptofuzz
        cd $SRC/cryptofuzz
        LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc) >/dev/null

        # Generate dictionary
        ./generate_dict

        # Copy fuzzer
        cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-nettle-with-libgmp
        # Copy dictionary
        cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-nettle-with-libgmp.dict
        # Copy seed corpus
        cp $SRC/cryptofuzz-corpora/libressl_latest.zip $OUT/cryptofuzz-nettle-with-libgmp_seed_corpus.zip
fi

# Compile Nettle (with mini gmp)
    mkdir $SRC/nettle-with-mini-gmp-install/
    cp -R $SRC/nettle $SRC/nettle-with-mini-gmp/
    cd $SRC/nettle-with-mini-gmp/
    bash .bootstrap
    export NETTLE_LIBDIR=`realpath ../nettle-with-mini-gmp-install`/lib
    if [[ $CFLAGS != *sanitize=memory* ]]
    then
        ./configure --enable-mini-gmp --disable-documentation --disable-openssl --prefix=`realpath ../nettle-with-mini-gmp-install` --libdir="$NETTLE_LIBDIR"
    else
        ./configure --enable-mini-gmp --disable-documentation --disable-openssl --disable-assembler --prefix=`realpath ../nettle-with-mini-gmp-install` --libdir="$NETTLE_LIBDIR"
    fi
    make -j$(nproc)
    make install

    export LIBNETTLE_A_PATH=$NETTLE_LIBDIR/libnettle.a
    export LIBHOGWEED_A_PATH=$NETTLE_LIBDIR/libhogweed.a
    export NETTLE_INCLUDE_PATH=`realpath ../nettle-with-mini-gmp-install/include`
    export LINK_FLAGS=""
    export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NETTLE"

    # Compile Cryptofuzz Nettle module
    cd $SRC/cryptofuzz/modules/nettle
    make -f Makefile-hogweed -B

# Compile Cryptofuzz
    cd $SRC/cryptofuzz
    LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -B -j$(nproc) >/dev/null

    # Generate dictionary
    ./generate_dict

    # Copy fuzzer
    cp $SRC/cryptofuzz/cryptofuzz $OUT/cryptofuzz-nettle-with-mini-gmp
    # Copy dictionary
    cp $SRC/cryptofuzz/cryptofuzz-dict.txt $OUT/cryptofuzz-nettle-with-mini-gmp.dict
    # Copy seed corpus
    cp $SRC/cryptofuzz-corpora/libressl_latest.zip $OUT/cryptofuzz-nettle-with-mini-gmp_seed_corpus.zip
