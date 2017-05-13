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

# build expat
cd libexpat/expat
./buildconf.sh
./configure --disable-shared --prefix=$SRC/install
make clean -s
make -j$(nproc) -s
make install
cd ../..

# build sqlite3
# Taken from https://github.com/google/oss-fuzz/blob/master/projects/sqlite3/build.sh

export ASAN_OPTIONS=detect_leaks=0

# Limit max length of data blobs and sql queries to prevent irrelevant OOMs.
# Also limit max memory page count to avoid creating large databases.
OLD_CFLAGS=$CFLAGS
export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=128000000 \
               -DSQLITE_MAX_SQL_LENGTH=128000000 \
               -DSQLITE_MAX_MEMORY=25000000 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
               -DSQLITE_DEBUG=1 \
               -DSQLITE_MAX_PAGE_COUNT=16384" 

cd sqlite3
./configure --disable-shared --prefix=$SRC/install
make clean -s
make -j$(nproc) -s
make install
cd ..
export CFLAGS=$OLD_CFLAGS

# build gdal
cd gdal
export LDFLAGS=${CXXFLAGS}
./configure --without-libtool --with-expat=$SRC/install --with-sqlite3=$SRC/install
make clean -s
make -j$(nproc) -s

./fuzzers/build_google_oss_fuzzers.sh
./fuzzers/build_seed_corpus.sh
