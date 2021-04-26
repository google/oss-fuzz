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

git submodule update --init --recursive
sed -i 's/-Werror//g' ./cmake/define.inc
mkdir debug && cd debug
cmake .. && cmake --build .

cd build/bin

# Now let's build the fuzzer.
$CC $CFLAGS -DLINUX -DUSE_LIBICONV -D_LINUX -D_M_X64 \
     -D_TD_LINUX  -D_TD_LINUX_64 \
     -I/src/tdengine/src/inc -I/src/tdengine/src/os/inc \
     -I/src/tdengine/src/util/inc -I/src/tdengine/src/common/inc \
     -I/src/tdengine/src/tsdb/inc -I/src/tdengine/src/query/inc \
     -o sql-fuzzer.o -c $SRC/sql-fuzzer.c

$CC $CFLAGS $LIB_FUZZING_ENGINE sql-fuzzer.o -o $OUT/sql-fuzzer \
     ../../../debug/src/common/CMakeFiles/common.dir/src/tglobal.c.o  \
     ../lib/libtaos_static.a ../lib/libtrpc.a ../lib/libquery.a \
     ../lib/libtsdb.a ../lib/libcommon.a ../lib/libtfs.a ../lib/libtutil.a \
     ../lib/liblz4.a ../lib/libosdetail.a ../lib/libos.a ../lib/libz.a  \
     ../lib/librmonotonic.a -lm -lrt -lpthread
