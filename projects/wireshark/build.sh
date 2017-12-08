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

export WIRESHARK_INSTALL_PATH="$WORK/install"
mkdir -p "$WIRESHARK_INSTALL_PATH"

# Prepare Samples directory
export SAMPLES_DIR="$WORK/samples"
mkdir -p "$SAMPLES_DIR"
cp -a $SRC/wireshark-fuzzdb/samples/* "$SAMPLES_DIR"

# compile static version of libs
# XXX, with static wireshark linking each fuzzer binary is ~240 MB (just libwireshark.a is 423 MBs).
# XXX, wireshark is not ready for including static plugins into binaries.
CONFOPTS="--disable-shared --enable-static --disable-plugins"

# disable optional dependencies
CONFOPTS="$CONFOPTS --without-pcap --without-ssl --without-gnutls"

# need only libs, disable programs
CONFOPTS="$CONFOPTS --disable-wireshark --disable-tshark --disable-sharkd \
             --disable-dumpcap --disable-capinfos --disable-captype --disable-randpkt --disable-dftest \
             --disable-editcap --disable-mergecap --disable-reordercap --disable-text2pcap \
             --without-extcap --disable-fuzzshark \
         "

# Fortify and asan don't like each other ... :(
sed -i '/AC_WIRESHARK_GCC_FORTIFY_SOURCE_CHECK/d' configure.ac
./autogen.sh
./configure --prefix="$WIRESHARK_INSTALL_PATH" $CONFOPTS --disable-warnings-as-errors

make "-j$(nproc)"
make install
$SRC/wireshark/tools/oss-fuzzshark/build.sh all
