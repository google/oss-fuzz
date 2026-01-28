#!/bin/bash -eu
# Copyright 2017 Google Inc.
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
tar -xzf $SRC/libxml2-2.9.7.tar.gz
cd libxml2-2.9.7
./configure --disable-shared --enable-static --disable-ipv6 --without-python --without-zlib --without-lzma
make -j$(nproc)
make install
export LIBXML_CFLAGS="-I$(pwd)/include"
export LIBXML_LIBS="-L$(pwd) -lxml2"
export XML_CFLAGS="$LIBXML_CFLAGS"
export XML_LIBS="$LIBXML_LIBS"
cd $SRC/wireshark

WIRESHARK_BUILD_PATH="$WORK/build"
mkdir -p "$WIRESHARK_BUILD_PATH"

# Prepare Samples directory
export SAMPLES_DIR="$WORK/samples"
mkdir -p "$SAMPLES_DIR"
cp -a $SRC/wireshark-fuzzdb/samples/* "$SAMPLES_DIR"

# Make sure we build fuzzshark.
CMAKE_DEFINES="-DBUILD_fuzzshark=ON"

# compile static version of libs
# XXX, with static wireshark linking each fuzzer binary is ~346 MB (just libwireshark.a is 761 MB).
# XXX, wireshark is not ready for including static plugins into binaries.
CMAKE_DEFINES="$CMAKE_DEFINES -DBUILD_SHARED_LIBS=OFF -DENABLE_PLUGINS=OFF"

# disable optional dependencies
CMAKE_DEFINES="$CMAKE_DEFINES -DENABLE_PCAP=OFF -DENABLE_GNUTLS=OFF"

# There is no need to manually disable programs via BUILD_xxx=OFF since the
# all-fuzzers targets builds the minimum required binaries. However we do have
# to disable the Qt GUI and sharkd or else the cmake step will fail.
CMAKE_DEFINES="$CMAKE_DEFINES -DBUILD_wireshark=OFF -DBUILD_stratoshark=OFF -DBUILD_sharkd=OFF"

cd "$WIRESHARK_BUILD_PATH"

cmake -GNinja \
      -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="-Wno-error=fortify-source -Wno-error=missing-field-initializers $CFLAGS" -DCMAKE_CXX_FLAGS="-Wno-error=fortify-source -Wno-error=missing-field-initializers $CXXFLAGS" \
      -DENABLE_WERROR=OFF -DOSS_FUZZ=ON $CMAKE_DEFINES \
      -DUSE_STATIC=ON $SRC/wireshark

ninja all-fuzzers -j$(expr $(nproc) / 2)

$SRC/wireshark/tools/oss-fuzzshark/build.sh all
