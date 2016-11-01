#!/bin/bash -eux
# Copyright 2016 Google Inc.
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

cd /src

cd fribidi
./bootstrap
./configure --enable-static=yes --enable-shared=no --with-pic=yes
# Don't run "make": it's broken. Run "make install".
make -j$(nproc) install

cd /src/libass

./autogen.sh
./configure --disable-asm
make -j$(nproc)

$CXX $CXXFLAGS -std=c++11 -I/src/libass \
    /src/libass_fuzzer.cc -o /out/libass_fuzzer \
    -lfuzzer libass/.libs/libass.a \
    -Wl,-Bstatic -lfontconfig  -lfribidi -lfreetype -lz -lpng12 -lexpat -Wl,-Bdynamic \
    $FUZZER_LDFLAGS

cp /src/*.dict /src/*.options /out/
