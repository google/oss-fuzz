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

cd /src/sqlite3

mkdir bld
cd bld

export ASAN_OPTIONS=detect_leaks=0
# Limit max length of data blobs and sql queries to prevent irrelevant OOMs.
export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=128000000 \
               -DSQLITE_MAX_SQL_LENGTH=128000000 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=128000000"
../configure
make -j$(nproc)
make sqlite3.c

$CC $CFLAGS -I. \
    /src/sqlite3/test/ossfuzz.c -o /out/sqlite3_fuzzer \
    -lfuzzer ./sqlite3.o $FUZZER_LDFLAGS

cp /src/*.options /src/*.dict /out/

