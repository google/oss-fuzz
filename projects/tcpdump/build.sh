#!/bin/bash -eu
# Copyright 2024 Google LLC
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

# Build libpcap (static) first
cd $SRC/libpcap
mkdir -p build && cd build
cmake .. \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DBUILD_SHARED_LIBS=OFF \
    -DDISABLE_DBUS=ON \
    -DDISABLE_BLUETOOTH=ON \
    -DDISABLE_USB=ON \
    -DDISABLE_RDMA=ON
make -j$(nproc) pcap_static
LIBPCAP_A="$SRC/libpcap/build/libpcap.a"
LIBPCAP_INC="$SRC/libpcap"

# Build tcpdump object files
cd $SRC/tcpdump
autoreconf -ivf 2>/dev/null || cmake -B build_tmp . 2>/dev/null || true

# Use CMake build
mkdir -p fuzz_build && cd fuzz_build
cmake .. \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_C_FLAGS="$CFLAGS -I${LIBPCAP_INC}" \
    -DPCAP_ROOT="$SRC/libpcap/build" \
    -DBUILD_SHARED_LIBS=OFF
make -j$(nproc) || true

# Collect all .o files
cd $SRC/tcpdump

# Build with autoconf instead if CMake objects
if [ ! -d fuzz_build ] || [ -z "$(find fuzz_build -name '*.o' 2>/dev/null)" ]; then
    autoreconf -ivf
    CFLAGS="$CFLAGS" ./configure \
        --with-pcap-include="$LIBPCAP_INC" \
        --with-pcap-lib="$(dirname $LIBPCAP_A)"
    make -j$(nproc) || true
fi

# Collect object files (exclude main tcpdump.o to avoid duplicate main)
ALL_OBJS=$(find . -name "*.o" ! -name "tcpdump.o" ! -name "CMakeFiles" 2>/dev/null | tr '\n' ' ')

# Build the fuzzer
$CC $CFLAGS -I. -I"$LIBPCAP_INC" \
    -c fuzz_tcpdump.c -o fuzz_tcpdump.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    fuzz_tcpdump.o $ALL_OBJS \
    "$LIBPCAP_A" \
    -o $OUT/fuzz_tcpdump

# Copy dictionary
cp $SRC/tcpdump/fuzz_tcpdump.dict $OUT/

# Seed corpus: pcap test files
mkdir -p /tmp/tcpdump_seeds
# Use tcpdump's own test pcap files as seed corpus
find $SRC/tcpdump/tests -name "*.pcap" -o -name "*.pcapng" 2>/dev/null | \
    head -50 | while read f; do
        # Strip pcap header (24 bytes global + 16 bytes per-record) to get raw packet
        # For fuzzing, use the full pcap file content prefixed with DLT byte
        dlt_byte="\x00"  # DLT_EN10MB index 0
        printf "$dlt_byte" > /tmp/tcpdump_seeds/$(basename "$f").fuzz
        tail -c +41 "$f" >> /tmp/tcpdump_seeds/$(basename "$f").fuzz 2>/dev/null || true
    done

# Also generate minimal synthetic seeds
printf '\x00\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01\x08\x00\x00\x00\x00\x00\x00\x00' > /tmp/tcpdump_seeds/icmp_ping.fuzz
printf '\x00\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\xb8\x6e\xc0\xa8\x01\x01\xc0\xa8\x01\x02\x00\x50\x04\xd2\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\xff\xff\x00\x00\x00\x00' > /tmp/tcpdump_seeds/tcp_syn.fuzz
printf '\x00\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11\x22\x33\x44\x55\xc0\xa8\x01\x01\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\x02' > /tmp/tcpdump_seeds/arp.fuzz

zip -j $OUT/fuzz_tcpdump_seed_corpus.zip /tmp/tcpdump_seeds/*.fuzz
