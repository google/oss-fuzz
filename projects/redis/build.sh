#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cd $SRC/redis

# Build Redis dependencies without instrumentation to avoid linker issues
CFLAGS_SAVE="$CFLAGS"
CXXFLAGS_SAVE="$CXXFLAGS"
unset CFLAGS
unset CXXFLAGS
export AFL_NOOPT=1

make -C deps hiredis linenoise lua hdr_histogram fpconv fast_float xxhash MALLOC=libc

export CFLAGS="${CFLAGS_SAVE}"
export CXXFLAGS="${CXXFLAGS_SAVE}"
unset AFL_NOOPT

# Build all Redis server object files with instrumentation
cd src

REDIS_INCLUDES="-I. -I../deps/hiredis -I../deps/lua/src -I../deps/hdr_histogram \
    -I../deps/fpconv -I../deps/fast_float -I../deps/xxhash"

REDIS_SRCS="threads_mngr.c memory_prefetch.c adlist.c quicklist.c ae.c anet.c dict.c \
  ebuckets.c eventnotifier.c iothread.c mstr.c entry.c kvstore.c fwtree.c estore.c \
  sds.c zmalloc.c lzf_c.c lzf_d.c pqsort.c zipmap.c sha1.c ziplist.c release.c \
  networking.c util.c object.c db.c replication.c rdb.c t_string.c t_list.c t_set.c \
  t_zset.c t_hash.c config.c aof.c pubsub.c multi.c debug.c sort.c intset.c syncio.c \
  cluster.c cluster_legacy.c cluster_slot_stats.c crc16.c endianconv.c \
  slowlog.c eval.c bio.c rio.c rand.c memtest.c syscheck.c crcspeed.c crccombine.c \
  crc64.c bitops.c sentinel.c notify.c setproctitle.c blocked.c hyperloglog.c latency.c \
  sparkline.c redis-check-rdb.c redis-check-aof.c geo.c lazyfree.c module.c evict.c \
  expire.c geohash.c geohash_helper.c childinfo.c defrag.c siphash.c rax.c t_stream.c \
  listpack.c localtime.c lolwut.c lolwut5.c lolwut6.c lolwut8.c acl.c tracking.c \
  socket.c tls.c sha256.c timeout.c setcpuaffinity.c monotonic.c mt19937-64.c \
  resp_parser.c call_reply.c script_lua.c script.c functions.c function_lua.c \
  commands.c strl.c connection.c unix.c logreqres.c keymeta.c chk.c hotkeys.c gcra.c"

for src_file in $REDIS_SRCS; do
    if [ -f "$src_file" ]; then
        $CC $CFLAGS -DREDIS_STATIC='' -std=gnu11 $REDIS_INCLUDES \
            -c "$src_file" -o "${src_file%.c}.o" || true
    fi
done

# Build server.c with renamed main to avoid linker conflict
if [ -f server.c ]; then
    $CC $CFLAGS -DREDIS_STATIC='' -std=gnu11 $REDIS_INCLUDES \
        -Dmain=redis_main -c server.c -o server.o
fi

# Build cluster_asm if present
if [ -f cluster_asm.c ]; then
    $CC $CFLAGS -DREDIS_STATIC='' $REDIS_INCLUDES \
        -c cluster_asm.c -o cluster_asm.o || true
fi

# Create static library, excluding redisassert.o (conflicts with debug.o)
ar rcs libredis-server.a *.o
ar d libredis-server.a redisassert.o 2>/dev/null || true

REDIS_LIBS="libredis-server.a \
    ../deps/hiredis/libhiredis.a \
    ../deps/lua/src/liblua.a \
    ../deps/hdr_histogram/libhdrhistogram.a \
    ../deps/fpconv/libfpconv.a \
    ../deps/fast_float/libfast_float.a \
    ../deps/xxhash/libxxhash.a \
    -lm -ldl -lpthread"

# Build fuzz_sds
$CC $CFLAGS -DREDIS_STATIC='' -std=gnu11 $REDIS_INCLUDES \
    -c $SRC/fuzz_sds.c -o fuzz_sds.o
$CXX $CXXFLAGS fuzz_sds.o -o $OUT/fuzz_sds \
    $LIB_FUZZING_ENGINE $REDIS_LIBS

# Build fuzz_rdb (needs --wrap=exit to intercept exit() calls in error paths)
$CC $CFLAGS -DREDIS_STATIC='' -std=gnu11 $REDIS_INCLUDES \
    -c $SRC/fuzz_rdb.c -o fuzz_rdb.o
$CXX $CXXFLAGS -Wl,--wrap=exit,--wrap=malloc,--wrap=calloc,--wrap=realloc \
    fuzz_rdb.o -o $OUT/fuzz_rdb \
    $LIB_FUZZING_ENGINE $REDIS_LIBS

# Copy dictionaries and options
cp $SRC/redis.dict $OUT/fuzz_sds.dict
cp $SRC/redis.dict $OUT/fuzz_rdb.dict
cp $SRC/fuzz_rdb.options $OUT/fuzz_rdb.options

# Create RDB seed corpus
mkdir -p /tmp/rdb_seeds
printf 'REDIS0012\xfe\x00\xfb\x00\x00\xff' > /tmp/rdb_seeds/minimal.rdb
printf 'REDIS0012\xfe\x00\xfb\x01\x00\x00\x03key\x05value\xff' > /tmp/rdb_seeds/string.rdb
printf 'REDIS0012\xfe\x00\xfb\x01\x00\x01\x03key\x01\x05value\xff' > /tmp/rdb_seeds/list.rdb
cd /tmp/rdb_seeds && zip $OUT/fuzz_rdb_seed_corpus.zip *.rdb
