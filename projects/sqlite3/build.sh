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

mkdir bld
cd bld

export ASAN_OPTIONS=detect_leaks=0

# Limit max length of data blobs and sql queries to prevent irrelevant OOMs.
# Also limit max memory page count to avoid creating large databases.
export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=128000000 \
               -DSQLITE_MAX_SQL_LENGTH=128000000 \
               -DSQLITE_MAX_MEMORY=25000000 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
               -DSQLITE_DEBUG=1 \
               -DSQLITE_MAX_PAGE_COUNT=16384"             
               
../configure
make -j$(nproc)
make sqlite3.c

$CC $CFLAGS -I. -c \
    $SRC/sqlite3/test/ossfuzz.c -o $SRC/sqlite3/test/ossfuzz.o

$CXX $CXXFLAGS \
    $SRC/sqlite3/test/ossfuzz.o -o $OUT/ossfuzz \
    $LIB_FUZZING_ENGINE ./sqlite3.o

cp $SRC/*.options $SRC/*.dict $SRC/*.zip $OUT/
