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
tar -xf libmicrohttpd-latest.tar.gz
cd libmicrohttpd*
./configure
make
make install

cd $SRC/libhttpserver
./bootstrap
mkdir build; cd build
../configure --enable-shared=no
make
make install

cd ../test/fuzz
$CXX $CXXFLAGS -std=c++11 basic_fuzzer.cc -o $OUT/basic_fuzzer $LIB_FUZZING_ENGINE /usr/local/lib/libhttpserver.a /usr/local/lib/libmicrohttpd.a -lgnutls
cp *.zip $OUT
