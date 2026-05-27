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

# build project (with rpcapd enabled so daemon.h / daemon.c are available)
mkdir build
cd build
cmake .. -DENABLE_REMOTE=ON
make
cd ..

# build existing fuzz targets
for target in pcap filter both
do
    $CC $CFLAGS -I. -c testprogs/fuzz/fuzz_$target.c -o fuzz_$target.o
    $CXX $CXXFLAGS fuzz_$target.o -o $OUT/fuzz_$target build/libpcap.a $LIB_FUZZING_ENGINE
done

# build rpcap client/server fuzz targets (previously missing from OSS-Fuzz)
# fuzz_rclient: exercises the RPCAP client-side network protocol parser
# fuzz_rserver: exercises rpcapd daemon_serviceloop() server-side protocol handling
for target in rclient rserver
do
    $CC $CFLAGS -I. -Irpcapd -c testprogs/fuzz/fuzz_$target.c -o fuzz_$target.o
    if [ "$target" = "rserver" ]; then
        # rserver needs daemon.c and log.c from rpcapd
        $CC $CFLAGS -I. -Irpcapd -c rpcapd/daemon.c  -o daemon.o
        $CC $CFLAGS -I. -Irpcapd -c rpcapd/log.c     -o log.o
        $CXX $CXXFLAGS fuzz_$target.o daemon.o log.o \
            -o $OUT/fuzz_$target build/libpcap.a $LIB_FUZZING_ENGINE
    else
        $CXX $CXXFLAGS fuzz_$target.o \
            -o $OUT/fuzz_$target build/libpcap.a $LIB_FUZZING_ENGINE
    fi
done

# export options files
cp testprogs/fuzz/fuzz_*.options $OUT/ 2>/dev/null || true

# seed corpora
cd $SRC/tcpdump/
zip -r fuzz_pcap_seed_corpus.zip tests/
cp fuzz_pcap_seed_corpus.zip $OUT/
cp fuzz_pcap_seed_corpus.zip $OUT/fuzz_rclient_seed_corpus.zip

cd $SRC/libpcap/testprogs/BPF
mkdir corpus
ls *.txt | while read i; do tail -1 $i > corpus/$i; done
zip -r fuzz_filter_seed_corpus.zip corpus/
cp fuzz_filter_seed_corpus.zip $OUT/
