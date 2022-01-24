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


function copy_lib
    {
    local fuzzer_path=$1
    local lib=$2
    cp $(ldd ${fuzzer_path} | grep "${lib}" | awk '{ print $3 }') ${OUT}/lib/ || true
    }

mkdir -p $OUT/lib

# build dependency
(
cd $SRC/libyang
mkdir build; cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_LYD_PRIV=ON -DCMAKE_INSTALL_PREFIX:PATH=/usr \
    -D CMAKE_BUILD_TYPE:String="Release" ..
make -j$(nproc)
make install
)

# build project
export ASAN_OPTIONS=detect_leaks=0
export CFLAGS="${CFLAGS} -DFUZZING_OVERRIDE_LLVMFuzzerTestOneInput"
export CXXFLAGS="${CXXFLAGS} -DFUZZING_OVERRIDE_LLVMFuzzerTestOneInput"
./bootstrap.sh
./configure --enable-libfuzzer --enable-static --enable-static-bin --sbindir=$SRC/bin
make -j$(nproc)
make install
cp ./lib/.libs/libfrr.so.0 $OUT/lib/
cp $SRC/bin/bgpd $OUT/
cp $SRC/bin/ospfd $OUT/
cp $SRC/bin/pimd $OUT/
cp $SRC/bin/zebra $OUT/

# build corpus
cd $SRC/corpi
find . -type d -maxdepth 1 | while read i; do zip -j $OUT/"$i"_seed_corpus.zip "$i"/*; done

find $OUT -maxdepth 1 -type f -executable | while read i; do
    grep "LLVMFuzzerTestOneInput" ${i} > /dev/null 2>&1 || continue
    patchelf --set-rpath '$ORIGIN/lib' ${i}
    copy_lib ${i} libpcre2
    copy_lib ${i} libyang
    copy_lib ${i} libelf
    copy_lib ${i} libjson-c
done

patchelf --remove-needed libpcre2-8.so.0 $OUT/lib/libyang.so.2
