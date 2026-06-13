#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cd $SRC/nsd

# Configure NSD
autoreconf -ivf
./configure \
    CC="$CC" \
    CFLAGS="$CFLAGS" \
    --with-ssl \
    --enable-debug

# Build all object files
make -j$(nproc) nsd || make nsd || true

# Collect NSD object files (exclude main nsd.o to avoid duplicate main)
NSD_OBJS=$(find . -maxdepth 1 -name "*.o" ! -name "nsd.o" | tr '\n' ' ')

# Build fuzzer
$CC $CFLAGS -I. \
    $SRC/fuzz_nsd_packet.c \
    $NSD_OBJS \
    -lssl -lcrypto \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_nsd_packet

# Seed corpus: minimal DNS queries
mkdir -p /tmp/nsd_seeds

# Minimal A query for example.com
printf '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' > /tmp/nsd_seeds/a_query.dns
printf '\x07example\x03com\x00\x00\x01\x00\x01'            >> /tmp/nsd_seeds/a_query.dns

# AAAA query
printf '\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' > /tmp/nsd_seeds/aaaa_query.dns
printf '\x07example\x03com\x00\x00\x1c\x00\x01'            >> /tmp/nsd_seeds/aaaa_query.dns

# AXFR query
printf '\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' > /tmp/nsd_seeds/axfr_query.dns
printf '\x07example\x03com\x00\x00\xfc\x00\x01'            >> /tmp/nsd_seeds/axfr_query.dns

zip -j $OUT/fuzz_nsd_packet_seed_corpus.zip /tmp/nsd_seeds/*.dns
