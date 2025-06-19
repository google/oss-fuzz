#!/bin/bash -eu
# Copyright 2020 Google Inc.
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
export ORIG_CFLAGS=${CFLAGS}
cd haproxy

# Fix some things in the Makefile where there are no options available
sed 's/COPTS += $(DEBUG) $(OPTIONS_CFLAGS) $(CFLAGS) $(ADDINC)/COPTS += $(DEBUG) $(OPTIONS_CFLAGS) $(CFLAGS) $(ADDINC) ${ORIG_CFLAGS}/g' -i Makefile
sed 's/LDOPTS = $(TARGET_LDFLAGS) $(OPTIONS_LDFLAGS) $(ADDLIB)/LDOPTS = $(TARGET_LDFLAGS) $(OPTIONS_LDFLAGS) $(ADDLIB) ${CXXFLAGS}/g' -i Makefile
make TARGET=generic CC=${CC} LD=${CXX} 

# Make a copy of the main file since it has many global functions we need to declare
# We dont want the main function but we need the rest of the stuff in haproxy.c
cd /src/haproxy
sed 's/int main(int argc/int main2(int argc/g' -i ./src/haproxy.c
sed 's/dladdr(main,/dladdr(main2,/g' -i ./src/tools.c
sed 's/(void*)main/(void*)main2/g' -i ./src/tools.c


SETTINGS="-Iinclude -g -DUSE_POLL -DUSE_TPROXY -DCONFIG_HAPROXY_VERSION=\"\" -DCONFIG_HAPROXY_DATE=\"\""

$CC $CFLAGS $SETTINGS -c -o ./src/haproxy.o ./src/haproxy.c
ar cr libhaproxy.a ./src/*.o

for fuzzer in hpack_decode cfg_parser; do
  cp $SRC/fuzz_${fuzzer}.c .
  $CC $CFLAGS $SETTINGS -c fuzz_${fuzzer}.c  -o fuzz_${fuzzer}.o
  $CXX -g $CXXFLAGS $LIB_FUZZING_ENGINE  fuzz_${fuzzer}.o libhaproxy.a -o $OUT/fuzz_${fuzzer}
done
