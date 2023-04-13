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

if [[ "$SANITIZER" != "memory" ]]; then
	#Disable code instrumentation
	CFLAGS_SAVE="$CFLAGS"
	CXXFLAGS_SAVE="$CXXFLAGS"
	unset CFLAGS
	unset CXXFLAGS
	export AFL_NOOPT=1
fi

# build libpcap
tar -xvzf libpcap-1.9.1.tar.gz
cd libpcap-1.9.1
./configure --disable-shared
make -j$(nproc)
make install
cd ..

if [[ "$SANITIZER" != "memory" ]]; then
	#Re-enable code instrumentation
	export CFLAGS="${CFLAGS_SAVE}"
	export CXXFLAGS="${CXXFLAGS_SAVE}"
	unset AFL_NOOPT
fi

# build project
cd ndpi
# Set LDFLAGS variable and `--with-only-libndpi` option as workaround for the
# "missing dependencies errors" in the introspector build. See #8939
LDFLAGS="-lpcap" ./autogen.sh --enable-fuzztargets --with-only-libndpi
make -j$(nproc)
# Copy fuzzers
ls fuzz/fuzz* | grep -v "\." | while read i; do cp $i $OUT/; done
# Copy dictionaries
cp fuzz/*.dict $OUT/
# Copy seed corpus
cp fuzz/*.zip $OUT/
# Copy configuration files
cp example/protos.txt $OUT/
cp example/categories.txt $OUT/
cp example/risky_domains.txt $OUT/
cp example/ja3_fingerprints.csv $OUT/
cp example/sha1_fingerprints.csv $OUT/
cp fuzz/ipv4_addresses.txt $OUT/
