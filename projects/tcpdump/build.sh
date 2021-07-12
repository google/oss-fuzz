#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

cd libpcap
mkdir build
cd build
cmake .. -DBUILD_SHARED_LIBS=OFF
make
make install
# seems broken for static build only, pkg-config broken as well
rm /usr/local/bin/pcap-config

cd ../../tcpdump
# build project
mkdir build
cd build
cmake ..
make
cp fuzz/fuzz* $OUT/

# export other associated stuff
cd ..
cp fuzz/fuzz_*.options $OUT/
# builds corpus
zip -r fuzz_pcap_seed_corpus.zip tests/*.pcap
cp fuzz_pcap_seed_corpus.zip $OUT/
