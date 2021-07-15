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

unset CPP
unset CXX
./configure
make -i


for fuzzname in utils parse; do
  $CC $CFLAGS $LIB_FUZZING_ENGINE -I./include -I./os/unix -I/usr/include/apr-1.0/ \
    $SRC/fuzz_${fuzzname}.c -o $OUT/fuzz_${fuzzname} \
    ./modules.o buildmark.o \
    -Wl,--start-group ./server/.libs/libmain.a \
                      ./modules/core/.libs/libmod_so.a \
                      ./modules/http/.libs/libmod_http.a \
                      ./server/mpm/event/.libs/libevent.a \
                      ./os/unix/.libs/libos.a \
                      /usr/lib/x86_64-linux-gnu/libaprutil-1.a \
                      /usr/lib/x86_64-linux-gnu/libapr-1.a \
    -Wl,--end-group -luuid -lpcre
done
