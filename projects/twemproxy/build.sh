#!/bin/bash -eu
# Copyright 2023 Google LLC
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

autoreconf -fvi
./configure --enable-debug=full
make all

$CC $CFLAGS -DHAVE_CONFIG_H \
    -I. -I src/ -D_GNU_SOURCE -I src/hashkit -I src/proto -I src/event -I contrib/yaml-0.2.5/include \
    -fno-strict-aliasing -Wall -c -o fuzzer.o src/fuzzer.c

$CXX -rdynamic -o fuzzer fuzzer.o \
    src/nc_core.o src/nc_connection.o src/nc_client.o src/nc_server.o src/nc_proxy.o src/nc_message.o src/nc_request.o src/nc_response.o \
    src/nc_mbuf.o src/nc_conf.o src/nc_stats.o src/nc_signal.o src/nc_rbtree.o src/nc_log.o src/nc_string.o src/nc_array.o src/nc_util.o \
	src/hashkit/libhashkit.a src/proto/libproto.a src/event/libevent.a contrib/yaml-0.2.5/src/.libs/libyaml.a -lpthread -lm $CFLAGS $LIB_FUZZING_ENGINE

cp fuzzer "$OUT"/fuzzer
cp "$SRC"/oss-fuzz-bloat/twemproxy/fuzzer_seed_corpus.zip "$OUT"/fuzzer_seed_corpus.zip
