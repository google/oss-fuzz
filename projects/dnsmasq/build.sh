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

git apply  --ignore-space-change --ignore-whitespace $SRC/fuzz_patch.patch 

export OSS_CFLAGS="$CFLAGS -g"

sed -i 's/CFLAGS        =/CFLAGS        = ${OSS_CFLAGS} /g' ./Makefile
sed -i 's/LDFLAGS       =/LDFLAGS       = ${OSS_CFLAGS} /g' ./Makefile

# Do some modificatiosn to the source
sed -i 's/recvmsg(/fuzz_recvmsg(/g' ./src/dhcp-common.c 
sed -i 's/recvmsg(/fuzz_recvmsg(/g' ./src/netlink.c 
sed -i 's/ioctl(/fuzz_ioctl(/g' ./src/dhcp.c
sed -i 's/ioctl(/fuzz_ioctl(/g' ./src/network.c

sed -i 's/if (errno != 0/if (errno == 123123/g' ./src/netlink.c

echo "" >> ./src/dnsmasq.c 
echo "ssize_t fuzz_recvmsg(int sockfd, struct msghdr *msg, int flags) {return -1;}" >> ./src/dnsmasq.c
echo "int fuzz_ioctl(int fd, unsigned long request, void *arg) {return -1;}" >> ./src/dnsmasq.c
make

# Remove main function and create an archive
cd ./src
sed -i 's/int main (/int main2 (/g' ./dnsmasq.c
sed -i 's/fuzz_recvmsg(/fuzz_recvmsg2(/g' ./dnsmasq.c
sed -i 's/fuzz_ioctl(/fuzz_ioctl2(/g' ./dnsmasq.c

rm dnsmasq.o
$CC $CFLAGS -c dnsmasq.c -o dnsmasq.o -I./ -DVERSION=\'\"UNKNOWN\"\' 
ar cr libdnsmasq.a *.o

sed -i 's/class/class2/g' ./dnsmasq.h
sed -i 's/new/new2/g' ./dnsmasq.h

# Build the fuzzers
for fuzz_name in dhcp6 rfc1035 auth dhcp util; do
    $CC $CFLAGS -c $SRC/fuzz_${fuzz_name}.c -I./ -I$SRC/ -DVERSION=\'\"UNKNOWN\"\' -g
    $CC $CFLAGS $LIB_FUZZING_ENGINE ./fuzz_${fuzz_name}.o libdnsmasq.a -o $OUT/fuzz_${fuzz_name}
done
