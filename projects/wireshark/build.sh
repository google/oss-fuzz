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

WIRESHARK_BUILD_PATH="$WORK/build"
mkdir -p "$WIRESHARK_BUILD_PATH"

export WIRESHARK_INSTALL_PATH="$WORK/install"
mkdir -p "$WIRESHARK_INSTALL_PATH"

# Prepare Samples directory
export SAMPLES_DIR="$WORK/samples"
mkdir -p "$SAMPLES_DIR"
cp -a $SRC/wireshark-fuzzdb/samples/* "$SAMPLES_DIR"

# compile static version of libs
# XXX, with static wireshark linking each fuzzer binary is ~338 MB (just libwireshark.a is 623 MBs).
# XXX, wireshark is not ready for including static plugins into binaries.
CMAKE_DEFINES="-DENABLE_STATIC=ON -DENABLE_PLUGINS=OFF"

# disable optional dependencies
CMAKE_DEFINES="$CMAKE_DEFINES -DENABLE_PCAP=OFF -DENABLE_GNUTLS=OFF"

# need only libs, disable programs
# TODO, add something like --without-extcap, which would disable all extcap binaries
CMAKE_DEFINES="$CMAKE_DEFINES -DBUILD_wireshark=OFF -DBUILD_tshark=OFF -DBUILD_sharkd=OFF \
             -DBUILD_dumpcap=OFF -DBUILD_capinfos=OFF -DBUILD_captype=OFF -DBUILD_randpkt=OFF -DBUILD_dftest=OFF \
             -DBUILD_editcap=OFF -DBUILD_mergecap=OFF -DBUILD_reordercap=OFF -DBUILD_text2pcap=OFF \
             -DBUILD_fuzzshark=OFF \
             -DBUILD_androiddump=OFF -DBUILD_randpktdump=OFF -DBUILD_udpdump=OFF \
         "

# Fortify and asan don't like each other ... :(
# TODO, right now -D_FORTIFY_SOURCE=2 is not added in cmake builds.
# sed -i '/AC_WIRESHARK_GCC_FORTIFY_SOURCE_CHECK/d' configure.ac

cd "$WIRESHARK_BUILD_PATH"

cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DCMAKE_INSTALL_PREFIX="$WIRESHARK_INSTALL_PATH" $CMAKE_DEFINES -DDISABLE_WERROR=ON $SRC/wireshark/

# disable leak checks, lemon is build with ASAN, and it leaks memory during building.
export ASAN_OPTIONS="detect_leaks=0"
make "-j$(nproc)"
make install

# make install didn't install config.h, install it manually
cp "$WIRESHARK_BUILD_PATH/config.h" "$WIRESHARK_INSTALL_PATH/include/wireshark/"

$SRC/wireshark/tools/oss-fuzzshark/build.sh all
