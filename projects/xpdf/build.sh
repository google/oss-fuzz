#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# Unpack the file
tar -zxvf xpdf-4.02.tar.gz   

# Now make the build directory
cd xpdf-4.02

# Make minor change in the CMakeFiles file.
sed -i 's/#--- object files needed by XpdfWidget/add_library(testXpdfStatic STATIC $<TARGET_OBJECTS:xpdf_objs>)\n#--- object files needed by XpdfWidget/' ./xpdf/CMakeLists.txt

# Build the project
mkdir build && cd build
export LD=$CXX
cmake ../ -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS"
make -i || true

# Build fuzzers
cp ../../fuzz_zxdoc.cc .
$CXX fuzz_zxdoc.cc -o $OUT/fuzz_zxdoc ./xpdf/libtestXpdfStatic.a ./fofi/libfofi.a ./goo/libgoo.a -I../ -I../goo -I../fofi -I. -I../xpdf $CXXFLAGS $LIB_FUZZING_ENGINE
