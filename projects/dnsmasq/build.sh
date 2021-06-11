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

export OSS_CFLAGS=$CFLAGS

sed -i 's/CFLAGS        =/CFLAGS        = ${OSS_CFLAGS} /g' ./Makefile
sed -i 's/LDFLAGS       =/LDFLAGS       = ${OSS_CFLAGS} /g' ./Makefile
make

# Remove main function and create an archive
cd ./src
sed -i 's/int main (/int main2 (/g' ./dnsmasq.c
rm dnsmasq.o
$CC $CFLAGS -c dnsmasq.c -o dnsmasq.o -I./ -DVERSION=\'\"UNKNOWN\"\' 
ar cr libdnsmasq.a *.o

sed -i 's/class/class2/g' ./dnsmasq.h
sed -i 's/new/new2/g' ./dnsmasq.h

# Now build fuzzer
for fuzz_name in util; do
    $CXX $CXXFLAGS -c ${SRC}/fuzz_${fuzz_name}.cpp -o ./fuzz_${fuzz_name}.o -I./ -DVERSION=\'\"UNKNOWN\"\'
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./fuzz_${fuzz_name}.o libdnsmasq.a -o $OUT/fuzz_${fuzz_name}
done
