#!/bin/bash -eu
# Copyright 2020 Google LLC
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

# Use ~ as sed delimiters instead of the usual "/" because C(XX)FLAGS may
# contain paths with slashes.
sed "s~CFLAGS=~CFLAGS+=~g" -i $SRC/lua/makefile
sed "s~MYLDFLAGS=~MYLDFLAGS=${CFLAGS} ~g" -i $SRC/lua/makefile
sed "s|CC= gcc|CC= ${CC}|g" -i $SRC/lua/makefile

cd $SRC/lua
make
cp ../fuzz_lua.c .
$CC $CFLAGS -c fuzz_lua.c -o fuzz_lua.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_lua.o -o $OUT/fuzz_lua ./liblua.a
