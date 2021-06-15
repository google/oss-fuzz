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

autoreconf -ivf
./configure --disable-lz4
make V=1
cd src/openvpn
rm openvpn.o
ar r libopenvpn.a *.o
for fuzzname in fuzz_base64 fuzz_dhcp fuzz_proxy fuzz_misc fuzz_buffer; do
    $CXX  -I../../src/compat/ -I../../ -I./ $CXXFLAGS -c $SRC/${fuzzname}.cpp -o ${fuzzname}.o
    $CXX ${CXXFLAGS} ${LIB_FUZZING_ENGINE} ./${fuzzname}.o -o $OUT/${fuzzname} \
        libopenvpn.a ../../src/compat/.libs/libcompat.a /usr/lib/x86_64-linux-gnu/libnsl.a \
        /usr/lib/x86_64-linux-gnu/libresolv.a /usr/lib/x86_64-linux-gnu/liblzo2.a \
        -lssl -lcrypto -ldl
done
