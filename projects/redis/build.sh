#!/bin/bash -eu
#
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
cd $SRC/redis
sed 's/LUA_LDFLAGS+= $(LDFLAGS)/LUA_LDFLAGS+=${CFLAGS}/g' -i deps/Makefile

LD="${CXX}"
export LDFLAGS="$CFLAGS"
export MYLDFLAGS="$CFLAGS"
make

# Recompile the server
cd $SRC/redis/src
cp $SRC/fuzz* .
sed 's/int main(/int main123(/g' -i server.c
$CC -pedantic -DREDIS_STATIC='' -std=c11 -g $CFLAGS \
    -I../deps/hiredis -I../deps/linenoise -I../deps/lua/src \
    -I../deps/hdr_histogram -DUSE_JEMALLOC -I../deps/jemalloc/include \
    -MMD -o server.o -c server.c

# Archive object files
ar rcs redis_lib.a ./*.o

# Compile and link the fuzzer
$CC $CFLAGS -g -pedantic -std=c11 -o fuzz_sds_and_utils.o -c ../tests/fuzzers/fuzz_sds_and_utils.c
$CC $CFLAGS $LIB_FUZZING_ENGINE fuzz_sds_and_utils.o redis_lib.a \
    ../deps/hiredis/libhiredis.a ../deps/lua/src/liblua.a \
    ../deps/jemalloc/lib/libjemalloc.a -lm -ldl -pthread -lrt -o fuzz_sds_and_utils

cp fuzz* $OUT/
