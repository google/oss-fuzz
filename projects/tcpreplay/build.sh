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

./autogen.sh
./configure --disable-local-libopts
make

# Recompile main
cd src
sed -i 's/main(/main2(/g' tcpbridge.c
$CC $CFLAGS -DHAVE_CONFIG_H -I. -I./.. -I./tcpedit -DTCPBRIDGE -D_U_="__attribute__((unused))" \
    -I/usr/include -MT tcpbridge-tcpbridge.o -MD -MP -MF .deps/tcpbridge-tcpbridge.Tpo \
    -c -o tcpbridge-tcpbridge.o `test -f 'tcpbridge.c' || echo './'`tcpbridge.c
cd ../

# Compile the fuzzer
$CC $CFLAGS $LIB_FUZZING_ENGINE -DTCPBRIDGE "-D_U_=__attribute__((unused))" ../fuzz_portmap.c -o $OUT/fuzz_portmap \
    ./src/tcpbridge-tcpbridge_opts.o ./src/tcpbridge-tcpbridge.o ./src/tcpbridge-bridge.o \
    ./src/tcpedit/libtcpedit.a ./src/common/libcommon.a ./lib/libstrl.a \
    /usr/lib/x86_64-linux-gnu/libopts.a \
    -I./src/ -I./src/tcpedit/ -I./ -lpcap  -lrt -lnsl
