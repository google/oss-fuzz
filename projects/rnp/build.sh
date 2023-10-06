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

cd $SRC

wget -qO- https://botan.randombit.net/releases/Botan-2.16.0.tar.xz | tar xJ
cd Botan-2.16.0
./configure.py --prefix=/usr --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" \
               --disable-modules=locking_allocator \
               --unsafe-fuzzer-mode --build-fuzzers=libfuzzer \
               --with-fuzzer-lib='FuzzingEngine'
make -j$(nproc)
make install

cd $SRC
mkdir fuzzing_corpus

cd $SRC/rnp/src/tests/data
find . -type f -print0 | xargs -0 -I bob -- cp bob $SRC/fuzzing_corpus/

# -DENABLE_SANITIZERS=0 because oss-fuzz will add the sanitizer flags in CFLAGS
# See https://github.com/google/oss-fuzz/pull/4189 to explain CMAKE_C_LINK_EXECUTABLE

cd $SRC
mkdir rnp-build
cd rnp-build
cmake \
    -DENABLE_SANITIZERS=0 \
    -DENABLE_FUZZERS=1 \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_LINK_EXECUTABLE="$CXX <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS>  -o <TARGET> <LINK_LIBRARIES>" \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_SHARED_LIBS=on \
    -DBUILD_TESTING=off \
    -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
    -DDOWNLOAD_SEXP:BOOL=ON \
    $SRC/rnp
make -j$(nproc)

FUZZERS=`find src/fuzzing -maxdepth 1 -type f -name "fuzz_*" -exec basename {} \;`
printf "Detected fuzzers: \n$FUZZERS\n"
for f in $FUZZERS; do
    cp src/fuzzing/$f "${OUT}/"
    patchelf --set-rpath '$ORIGIN/lib' "${OUT}/$f" || echo "patchelf failed with $?, ignoring."
    zip -j -r "${OUT}/${f}_seed_corpus.zip" $SRC/fuzzing_corpus/
done

mkdir -p "${OUT}/lib"
cp src/lib/librnp.so.0 "${OUT}/lib/"
cp /usr/lib/libbotan-2.so.16 "${OUT}/lib/"
cp /lib/x86_64-linux-gnu/libjson-c.so.* "${OUT}/lib/"
