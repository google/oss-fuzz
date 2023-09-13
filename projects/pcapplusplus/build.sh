#!/bin/bash -eu
#
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

TARGETS_DIR=build/

# Build libpcap
cd $SRC/libpcap/
./autogen.sh
./configure --enable-shared=no
make -j$(nproc)

# Build PcapPlusPlus linking statically against the built libpcap
cd $SRC/PcapPlusPlus
LIBPCAP_PATH=$SRC/libpcap/
cmake -DPCAPPP_BUILD_FUZZERS=ON -DPCAPPP_BUILD_TESTS=OFF -DPCAPPP_BUILD_EXAMPLES=OFF -DPCAP_INCLUDE_DIR="${LIBPCAP_PATH}/" -DPCAP_LIBRARY="${LIBPCAP_PATH}/libpcap.a" -S . -B $TARGETS_DIR
cmake --build $TARGETS_DIR -j

# Copy target and options
cp $TARGETS_DIR/Tests/Fuzzers/FuzzTarget $OUT
cp $(ldd $OUT/FuzzTarget | cut -d" " -f3) $OUT
cp $SRC/default.options $OUT/FuzzTarget.options

# Copy corpora
cd $SRC/tcpdump
zip -jr FuzzTarget_seed_corpus.zip tests/*.pcap
cp FuzzTarget_seed_corpus.zip $OUT/
