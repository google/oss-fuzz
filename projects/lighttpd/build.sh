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
./configure --without-pcre --enable-static
make
cd src
$CC $CFLAGS -c $SRC/fuzz_burl.c -I. -I../include
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_burl.o lighttpd-burl.o lighttpd-buffer.o lighttpd-base64.o lighttpd-ck.o -o $OUT/fuzz_burl

$CC $CFLAGS -c $SRC/fuzz_utils.c -I. -I../include
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_utils.o lighttpd-buffer.o lighttpd-base64.o lighttpd-ck.o -o $OUT/fuzz_utils

$CC $CFLAGS -DHAVE_CONFIG_H -c $SRC/fuzz_request.c -I. -I.. -I../include
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_request.o lighttpd-request.o lighttpd-burl.o lighttpd-buffer.o lighttpd-base64.o lighttpd-array.o lighttpd-http_header.o lighttpd-http_kv.o lighttpd-ck.o lighttpd-log.o lighttpd-sock_addr.o -o $OUT/fuzz_request
