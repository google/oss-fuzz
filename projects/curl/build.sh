#!/bin/bash -eu
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

echo "CC: $CC"
echo "CXX: $CXX"
echo "LIB_FUZZING_ENGINE: $LIB_FUZZING_ENGINE"
echo "CFLAGS: $CFLAGS"
echo "CXXFLAGS: $CXXFLAGS"

# Make an install directory
export INSTALLDIR=/tmp/curl_install

# Compile curl
pushd /tmp/curl
./buildconf
./configure --prefix=${INSTALLDIR} --disable-shared --enable-debug --enable-maintainer-mode --disable-symbol-hiding --disable-threaded-resolver --enable-ipv6 --with-random=/dev/null --without-ssl
make -j$(nproc)
make install
popd

# Build the fuzzer.
./buildconf
./configure
make
make check
make zip

cp -v curl_fuzzer curl_fuzzer_seed_corpus.zip $OUT/

# Copy dictionary and options file to $OUT.
cp $SRC/*.dict $SRC/*.options $OUT/
