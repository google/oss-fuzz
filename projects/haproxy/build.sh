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
cd $SRC/haproxy

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

for fuzzer in hpack_decode cfg_parser h1_parse; do
  cp $SRC/fuzz_${fuzzer}.c .
  $CC $CFLAGS $SETTINGS -c fuzz_${fuzzer}.c  -o fuzz_${fuzzer}.o
  $CXX -g $CXXFLAGS $LIB_FUZZING_ENGINE  fuzz_${fuzzer}.o libhaproxy.a -o $OUT/fuzz_${fuzzer}
done

# Copy dictionary and create seed corpus for H1 parser fuzzer
cp $SRC/fuzz_h1_parse.dict $OUT/fuzz_h1_parse.dict

mkdir -p "$WORK/h1_seeds"
# Generate seed HTTP/1 requests and responses (first byte: 0=req, 1=resp)
printf '\x00GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > "$WORK/h1_seeds/get_simple"
printf '\x00POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\nContent-Type: application/json\r\n\r\n{"key":"val"}' > "$WORK/h1_seeds/post_cl"
printf '\x00POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n' > "$WORK/h1_seeds/post_chunked"
printf '\x00GET /page HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\nCookie: s=abc\r\nUser-Agent: Mozilla/5.0\r\nX-Forwarded-For: 10.0.0.1\r\n\r\n' > "$WORK/h1_seeds/get_multi"
printf '\x00GET /old HTTP/1.0\r\nHost: example.com\r\n\r\n' > "$WORK/h1_seeds/get_http10"
printf '\x00GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n' > "$WORK/h1_seeds/websocket"
printf '\x00CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n' > "$WORK/h1_seeds/connect"
printf '\x00HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n' > "$WORK/h1_seeds/head"
printf '\x00OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n' > "$WORK/h1_seeds/options"
printf '\x01HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello' > "$WORK/h1_seeds/resp_200"
printf '\x01HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\nContent-Length: 0\r\n\r\n' > "$WORK/h1_seeds/resp_301"
printf '\x01HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n' > "$WORK/h1_seeds/resp_chunked"
printf '\x01HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n<html></html>' > "$WORK/h1_seeds/resp_connclose"
printf '\x01HTTP/1.1 100 Continue\r\n\r\n' > "$WORK/h1_seeds/resp_100"
printf '\x01HTTP/1.1 204 No Content\r\n\r\n' > "$WORK/h1_seeds/resp_204"
zip -j "$OUT/fuzz_h1_parse_seed_corpus.zip" "$WORK"/h1_seeds/*

# build vtest for run_tests.sh
cd $SRC/VTest2
make vtest
# vtest binary is in $SRC/VTest2/vtest
