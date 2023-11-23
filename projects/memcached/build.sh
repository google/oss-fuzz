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
cd vendor && ./fetch.sh && cd ../
git apply $SRC/patch.diff
./autogen.sh
./configure --enable-proxy
make

mv $SRC/fuzzer_proxy.c $SRC/memcached/
cd $SRC/memcached

$CC $CFLAGS $LIB_FUZZING_ENGINE -Ivendor/liburing/src/include \
    -Ivendor/lua/src \
    -L /usr/local/lib \
    -DHAVE_CONFIG_H -L ./vendor/lua/src \
    -g -O2 -pthread -levent -lm -ldl fuzzer_proxy.c \
    memcached-memcached.o memcached-hash.o memcached-jenkins_hash.o \
    memcached-murmur3_hash.o memcached-slabs.o memcached-items.o \
    memcached-assoc.o memcached-thread.o memcached-daemon.o memcached-stats_prefix.o \
    memcached-util.o memcached-cache.o memcached-bipbuffer.o memcached-base64.o \
    memcached-logger.o memcached-crawler.o memcached-itoa_ljust.o memcached-slab_automove.o \
    memcached-authfile.o memcached-restart.o memcached-proto_text.o memcached-proto_bin.o \
    memcached-proto_proxy.o memcached-proxy_xxhash.o memcached-proxy_await.o \
    memcached-proxy_ustats.o memcached-proxy_jump_hash.o memcached-proxy_request.o \
    memcached-proxy_network.o memcached-proxy_lua.o memcached-proxy_config.o \
    memcached-proxy_ring_hash.o memcached-proxy_internal.o memcached-md5.o \
    memcached-extstore.o memcached-crc32c.o memcached-storage.o memcached-slab_automove_extstore.o \
    memcached-proxy_ratelim.o \
    vendor/lua/src/liblua.a /usr/local/lib/libevent.a vendor/mcmc/mcmc.o -o fuzzer_proxy

python3 $SRC/generate_corpus.py

cp $SRC/memcached/fuzzer_proxy $OUT/
cp $SRC/*.options $OUT/
cp *seed_corpus.zip $OUT/
