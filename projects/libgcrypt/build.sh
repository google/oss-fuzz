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

tar -xf libgpg-error-1.41.tar.bz2
cd libgpg-error-1.41
./configure
#make
#make install

#make clean
./configure --enable-static
make
make install

# Build libgcrypt
cd $SRC/
cd libgcrypt/
./autogen.sh
./configure --enable-maintainer-mode --enable-static
make

# Now build the fuzzer
cp $SRC/fuzz_* .
$CC $CFLAGS -c fuzz_str.c -I./src -I./random/ -I./
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_str.o -o $OUT/fuzz_str \
    ./random/.libs/librandom.a ./src/.libs/libgcrypt.a ./cipher/.libs/libcipher.a \
    ../libgpg-error-1.41/src/.libs/libgpg-error.a
