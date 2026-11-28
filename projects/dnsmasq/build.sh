#!/bin/bash -eu
# Copyright 2021 Google LLC
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

export ASAN_OPTIONS="detect_leaks=0"

#git apply  --ignore-space-change --ignore-whitespace $SRC/fuzz_patch.patch 

export OSS_CFLAGS="$CFLAGS -g"

sed -i 's/CFLAGS        =/CFLAGS        = ${OSS_CFLAGS} /g' ./Makefile
sed -i 's/LDFLAGS       =/LDFLAGS       = ${OSS_CFLAGS} /g' ./Makefile

# Do some modificatiosn to the source
#sed -i 's/recvmsg(/fuzz_recvmsg(/g' ./src/dhcp-common.c 
#sed -i 's/recvmsg(/fuzz_recvmsg(/g' ./src/netlink.c 
#sed -i 's/ioctl(/fuzz_ioctl(/g' ./src/dhcp.c
#sed -i 's/ioctl(/fuzz_ioctl(/g' ./src/network.c

#sed -i 's/if (errno != 0/if (errno == 123123/g' ./src/netlink.c

#echo "" >> ./src/dnsmasq.c 
#echo "ssize_t fuzz_recvmsg(int sockfd, struct msghdr *msg, int flags) {return -1;}" >> ./src/dnsmasq.c
#echo "int fuzz_ioctl(int fd, unsigned long request, void *arg) {return -1;}" >> ./src/dnsmasq.c
make

# Remove main function and create an archive
cd ./src
sed -i 's/int main (/int main2 (/g' ./dnsmasq.c
#sed -i 's/fuzz_recvmsg(/fuzz_recvmsg2(/g' ./dnsmasq.c
#sed -i 's/fuzz_ioctl(/fuzz_ioctl2(/g' ./dnsmasq.c

rm dnsmasq.o
$CC $CFLAGS -c dnsmasq.c -o dnsmasq.o -I./ -DVERSION=\'\"UNKNOWN\"\' 
ar cr libdnsmasq.a *.o

# Build new C fuzzers against libdnsmasq.a.
# Must be before the sed class/new renaming below (these are C, not C++).
# CWD is $SRC/dnsmasq/src/ — -I./ picks up dnsmasq.h, -I$SRC/ picks up
# any headers copied into the oss-fuzz project directory.
for fuzzer in fuzz_dns fuzz_forward fuzz_dhcp_reply; do
  $CC $CFLAGS -c $SRC/${fuzzer}.c \
      -I./ -I$SRC/ \
      -DVERSION=\'\"UNKNOWN\"\' \
      -o ${fuzzer}.o
  $CC $CFLAGS $LIB_FUZZING_ENGINE \
      ./${fuzzer}.o libdnsmasq.a \
      -o $OUT/${fuzzer}
done

# fuzz_dhcp6_reply defines get_client_mac() as a stub to prevent the 500ms
# nanosleep loop in dhcp6.c's real implementation.  dhcp6.o is extracted from
# libdnsmasq.a (it provides dhcp6_reply), bringing its own get_client_mac
# definition along — causing a duplicate symbol.  --allow-multiple-definition
# resolves this: the linker keeps the first definition (our stub, from
# fuzz_dhcp6_reply.o, processed before the archive).
$CC $CFLAGS -c $SRC/fuzz_dhcp6_reply.c \
    -I./ -I$SRC/ \
    -DVERSION=\'\"UNKNOWN\"\' \
    -o fuzz_dhcp6_reply.o
$CC $CFLAGS $LIB_FUZZING_ENGINE \
    -Wl,--allow-multiple-definition \
    ./fuzz_dhcp6_reply.o libdnsmasq.a \
    -o $OUT/fuzz_dhcp6_reply

sed -i 's/class/class2/g' ./dnsmasq.h
sed -i 's/new/new2/g' ./dnsmasq.h

# Build the fuzzers
$CXX $CXXFLAGS -c $SRC/fuzz_util.cc -I./ -I$SRC/ -DVERSION=\'\"UNKNOWN\"\' -g
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./fuzz_util.o libdnsmasq.a -o $OUT/fuzz_util

# Seed corpora for new fuzzers
# fuzz_dns + fuzz_forward share the same DNS wire-format input
printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
    > "$WORK/dns_seed.bin"
printf '\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01' \
    >> "$WORK/dns_seed.bin"
zip -j "$OUT/fuzz_dns_seed_corpus.zip"     "$WORK/dns_seed.bin"
zip -j "$OUT/fuzz_forward_seed_corpus.zip" "$WORK/dns_seed.bin"

# fuzz_dhcp_reply — minimal DHCPv4 DISCOVER
{
  printf '\x01\x01\x06\x00\xde\xad\xbe\xef\x00\x00\x00\x00'
  printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
  printf '\xde\xad\xbe\xef\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
  printf '%0.s\x00' {1..64}
  printf '%0.s\x00' {1..128}
  printf '\x63\x82\x53\x63\x35\x01\x01\xff'
} > "$WORK/dhcp_reply_seed.bin"
zip -j "$OUT/fuzz_dhcp_reply_seed_corpus.zip" "$WORK/dhcp_reply_seed.bin"

# fuzz_dhcp6_reply — minimal DHCPv6 SOLICIT with DUID-LL
{
  printf '\x01\xde\xad\xbe'
  printf '\x00\x01\x00\x0a'
  printf '\x00\x03\x00\x01\xde\xad\xbe\xef\x00\x01'
} > "$WORK/dhcp6_reply_seed.bin"
zip -j "$OUT/fuzz_dhcp6_reply_seed_corpus.zip" "$WORK/dhcp6_reply_seed.bin"
