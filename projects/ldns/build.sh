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

cd $SRC/ldns

# Build ldns as a static library
autoreconf -ivf
./configure \
    CC="$CC" \
    CFLAGS="$CFLAGS" \
    --disable-shared \
    --enable-static \
    --with-ssl \
    --disable-dane-verify \
    --disable-examples \
    --disable-drill \
    --without-pyldns
make -j$(nproc) || make

LDNS_A=$(find . -name "libldns.a" | head -1)

# Build wire format fuzzer
$CC $CFLAGS -I. -I./include \
    $SRC/fuzz_ldns_wire.c \
    "$LDNS_A" -lssl -lcrypto \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_ldns_wire

# Build RR text parser fuzzer
$CC $CFLAGS -I. -I./include \
    $SRC/fuzz_ldns_rr.c \
    "$LDNS_A" -lssl -lcrypto \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_ldns_rr

# Seed corpus: well-formed DNS messages
mkdir -p /tmp/ldns_seeds

# Minimal valid A-record response (www.example.com -> 93.184.216.34)
printf '\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'  > /tmp/ldns_seeds/a_response.dns
printf '\x03www\x07example\x03com\x00\x00\x01\x00\x01'     >> /tmp/ldns_seeds/a_response.dns
printf '\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22' >> /tmp/ldns_seeds/a_response.dns

# Minimal valid query (A record for example.com)
printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'  > /tmp/ldns_seeds/a_query.dns
printf '\x07example\x03com\x00\x00\x01\x00\x01'             >> /tmp/ldns_seeds/a_query.dns

# AAAA query
printf '\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'  > /tmp/ldns_seeds/aaaa_query.dns
printf '\x07example\x03com\x00\x00\x1c\x00\x01'             >> /tmp/ldns_seeds/aaaa_query.dns

zip -j $OUT/fuzz_ldns_wire_seed_corpus.zip /tmp/ldns_seeds/*.dns

# Seed for RR text parser
mkdir -p /tmp/ldns_rr_seeds
echo 'www.example.com. 3600 IN A 93.184.216.34' > /tmp/ldns_rr_seeds/a_record.txt
echo 'mail.example.com. 3600 IN MX 10 mail.example.com.' > /tmp/ldns_rr_seeds/mx_record.txt
echo 'example.com. 3600 IN NS ns1.example.com.' > /tmp/ldns_rr_seeds/ns_record.txt
echo 'example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 300' > /tmp/ldns_rr_seeds/soa_record.txt
echo 'example.com. 3600 IN TXT "v=spf1 include:example.com ~all"' > /tmp/ldns_rr_seeds/txt_record.txt
zip -j $OUT/fuzz_ldns_rr_seed_corpus.zip /tmp/ldns_rr_seeds/*.txt
