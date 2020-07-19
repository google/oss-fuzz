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

wget -qO- https://botan.randombit.net/releases/Botan-2.12.1.tar.xz | tar xvJ
cd Botan-2.12.1
./configure.py --prefix=/usr --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" \
               --disable-modules=locking_allocator \
               --unsafe-fuzzer-mode --build-fuzzers=libfuzzer \
               --with-fuzzer-lib='FuzzingEngine'
make
make install
cd ..

mkdir rnp-build
cd rnp-build
cmake \
    -DENABLE_SANITIZERS=1 \
    -DENABLE_FUZZING=1 \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_SHARED_LIBS=on \
    -DBUILD_TESTING=off \
    ../rnp/
make

FUZZERS="fuzz_dump fuzz_keyring"
for f in $FUZZERS; do
    cp src/fuzzing/$f "${OUT}/"
    chrpath -r '$ORIGIN/lib' "${OUT}/$f"
done

mkdir -p "${OUT}/lib"
cp src/lib/librnp-0.so.0 "${OUT}/lib/"
cp /usr/lib/libbotan-2.so.12 "${OUT}/lib/"
cp /lib/x86_64-linux-gnu/libjson-c.so.2 "${OUT}/lib/"
