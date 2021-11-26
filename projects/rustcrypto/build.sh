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

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_RUSTCRYPTO -DCRYPTOFUZZ_NO_OPENSSL"
export LIBFUZZER_LINK="$LIB_FUZZING_ENGINE"

rm -f /usr/local/bin/cargo

curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env

# Install Boost headers
cd $SRC/
tar jxf boost_1_74_0.tar.bz2
cd boost_1_74_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
cp -R boost/ /usr/include/

cd $SRC/cryptofuzz/
python gen_repository.py

rm extra_options.h
echo -n '"' >>extra_options.h
echo -n '--force-module=RustCrypto ' >>extra_options.h
echo -n '--operations=' >>extra_options.h
echo -n    'Digest,' >>extra_options.h
echo -n    'HMAC,' >>extra_options.h
echo -n    'CMAC,' >>extra_options.h
echo -n    'SymmetricEncrypt,' >>extra_options.h
echo -n    'SymmetricDecrypt,' >>extra_options.h
echo -n    'KDF_HKDF,' >>extra_options.h
echo -n    'KDF_ARGON2,' >>extra_options.h
echo -n    'KDF_BCRYPT,' >>extra_options.h
echo -n    'KDF_PBKDF2,' >>extra_options.h
echo -n    'KDF_SCRYPT,' >>extra_options.h
echo -n    'BignumCalc_Mod_2Exp256' >>extra_options.h
echo -n '"' >>extra_options.h

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

cd $SRC/cryptofuzz/modules/botan/
make -j$(nproc) -f Makefile-oracle

cd $SRC/cryptofuzz/modules/rustcrypto/
if [[ $CFLAGS != *-m32* ]]
then
    make
else
    rustup target add i686-unknown-linux-gnu
    make -f Makefile.i386
fi

cd $SRC/cryptofuzz/
make -j$(nproc)

cp $SRC/cryptofuzz/cryptofuzz $OUT/

# Create seed corpus
unzip -n $SRC/corpus_cryptofuzz.zip -d $SRC/cryptofuzz_seed_corpus/
cd $SRC/cryptofuzz_seed_corpus
zip -r $SRC/cryptofuzz_seed_corpus.zip .
cp $SRC/cryptofuzz_seed_corpus.zip $OUT/
