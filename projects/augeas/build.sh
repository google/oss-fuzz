#!/bin/bash -eu
#
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


./autogen.sh
./configure --enable-static --disable-shared --without-selinux
make -j$(nproc)

sed -i '31 i\#ifdef __cplusplus'\\n'\extern "C" {'\\n'\#endif'\\n src/fa.h
sed -i '326 i\#ifdef __cplusplus'\\n'\}'\\n'\#endif'\\n src/fa.h

ASAN_OPTIONS=detect_leaks=0

cp $SRC/augeas_escape_name_fuzzer.cc .
cp $SRC/augeas_fa_fuzzer.cc .
cp $SRC/augeas_api_fuzzer.cc .


for fuzzer in augeas_api_fuzzer augeas_escape_name_fuzzer augeas_fa_fuzzer; do
    $CXX $CXXFLAGS -std=c++11 -Isrc/ `xml2-config --cflags` \
        $fuzzer.cc -o $OUT/$fuzzer $LIB_FUZZING_ENGINE \
        src/.libs/libaugeas.a src/.libs/libfa.a ./gnulib/lib/.libs/libgnu.a \
        /usr/lib/x86_64-linux-gnu/libxml2.a
done
