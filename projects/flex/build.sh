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

export ASAN_OPTIONS="detect_leaks=0"

./autogen.sh
./configure
make V=1

git apply $SRC/flex-patch.diff
cd src
$CC $CFLAGS -c main.c -DM4=2 -o main.o
cd ../

# Remove some object files we dont need. This is needed because we will link to
# all othero bject files in the src folder.
mv ./src/stage1*.o /tmp/
mv ./src/libmain.o /tmp/
mv ./src/flex-main.o /tmp/
mv ./src/libyywrap.o /tmp/

$CC $CFLAGS -c $SRC/fuzz-scanopt.c -I$SRC/flex/src
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./fuzz-scanopt.o ./src/*.o -o $OUT/fuzz-scanopt

$CC $CFLAGS -c $SRC/fuzz-main.c -I$SRC/flex/src
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./fuzz-main.o ./src/*.o -o $OUT/fuzz-main

cp $SRC/*.options $OUT/
