#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

#compile and link statically dependencies
cd ..
cd libgpg-error
./autogen.sh
./configure --disable-doc --enable-static --disable-shared
make
make install
cd ..
cd libgcrypt
./autogen.sh
./configure --disable-doc --enable-static --disable-shared
make
make install
cd ..
cd libassuan
./autogen.sh
./configure --disable-doc --enable-static --disable-shared
make
make install
cd ..
cd libksba
./autogen.sh
./configure --disable-doc --enable-static --disable-shared
make
make install
cd ..
cd npth
./autogen.sh
./configure --disable-doc --enable-static --disable-shared
make
make install
cd ..


# build project
cd gnupg
mkdir tests/fuzz
cp ../fuzz_* tests/fuzz
git apply ../fuzz.diff
./autogen.sh
./configure --disable-doc --enable-maintainer-mode
make -j$(nproc) all

# build fuzzers
cd tests/fuzz
#export other associated stuff
cp *.options $OUT/
cp fuzz_*_seed_corpus.zip $OUT/

ls fuzz_*.c | cut -d_ -f2 | cut -d. -f1 | while read target
do
    $CC $CFLAGS -DHAVE_CONFIG_H -I. -I../..  -I../../common -I../../g10 -c fuzz_$target.c -o fuzz_$target.o

    $CXX $CXXFLAGS -std=c++11 -DHAVE_CONFIG_H fuzz_$target.o -o $OUT/fuzz_$target ../../g10/libgpg.a ../../kbx/libkeybox.a ../../common/libcommon.a ../../common/libgpgrl.a $LIB_FUZZING_ENGINE -lgcrypt -lgpg-error -lassuan -lnpth
done
