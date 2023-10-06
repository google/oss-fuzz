#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

export ASAN_OPTIONS=alloc_dealloc_mismatch=0

if [[ $CFLAGS = *sanitize=address* ]]
then
    export CXXFLAGS="$CXXFLAGS -DASAN"
fi

if [[ $CFLAGS = *sanitize=memory* ]]
then
    export CXXFLAGS="$CXXFLAGS -DMSAN"
fi

if [[ $SANITIZER = coverage ]]
then
    export CXXFLAGS="$CXXFLAGS -fno-use-cxa-atexit"
fi

# Avoid forcing -stdlib=libc++ during compilation to avoid clutter with
# protobuf. We enable -stdlib=libc++ again once we link the fuzzer (to
# staticaly compiled libs).
OLD_CXXFLAGS="${CXXFLAGS}"
export CXXFLAGS=`echo $CXXFLAGS | sed -e "s/-stdlib=libc++//g"`
cd $SRC/protobuf-c/
./autogen.sh
./configure --enable-static=yes --enable-shared=false

make -j$(nproc)
make install

cd $SRC/fuzzing-headers/
./install.sh

cd $SRC/protobuf-c-fuzzers/
cp $SRC/protobuf-c/t/test-full.proto $SRC/protobuf-c-fuzzers/
export PATH=$PATH:$SRC/protobuf-c/protoc-c
protoc --c_out=. -I. -I/usr/local/include test-full.proto

CXXFLAGS="${OLD_CXXFLAGS}"
$CC $CFLAGS test-full.pb-c.c -I $SRC/protobuf-install -I $SRC/protobuf-c -c -o test-full.pb-c.o
$CXX $CXXFLAGS fuzzer.cpp -I $SRC/protobuf-install -I $SRC/protobuf-c test-full.pb-c.o $SRC/protobuf-c/protobuf-c/.libs/libprotobuf-c.a $LIB_FUZZING_ENGINE -o $OUT/fuzzer
