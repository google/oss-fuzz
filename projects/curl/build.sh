#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

./buildconf
./configure --disable-shared --enable-debug --enable-maintainer-mode --disable-symbol-hiding --disable-threaded-resolver --enable-ipv6 --with-random=/dev/null
make -j$(nproc)
$CXX $CXXFLAGS $SRC/curl_fuzzer.cc -Iinclude lib/.libs/libcurl.a \
  -o $OUT/curl_fuzzer \
  -Wl,-Bstatic -lssl -lcrypto -lz -lfuzzer -Wl,-Bdynamic

#  /usr/lib/x86_64-linux-gnu/libssl.a \
#  /usr/lib/x86_64-linux-gnu/libcrypto.a \

cp $SRC/*.dict $SRC/*.options $OUT/
