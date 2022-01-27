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

# Unpack the file and cd into it
tar -zxf xpdf-latest.tar.gz
dir_name=`tar -tzf xpdf-latest.tar.gz | head -1 | cut -f1 -d"/"`
cd $dir_name

# Make minor change in the CMakeFiles file.
sed -i 's/#--- object files needed by XpdfWidget/add_library(testXpdfStatic STATIC $<TARGET_OBJECTS:xpdf_objs>)\n#--- object files needed by XpdfWidget/' ./xpdf/CMakeLists.txt

# Build the project
mkdir build && cd build
export LD=$CXX
cmake ../ -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DOPI_SUPPORT=ON -DMULTITHREADED=0 -DCMAKE_DISABLE_FIND_PACKAGE_Qt4=1 \
  -DCMAKE_DISABLE_FIND_PACKAGE_Qt5Widgets=1 -DSPLASH_CMYK=ON
make -i || true

# Build fuzzers
for fuzzer in zxdoc pdfload; do
    cp ../../fuzz_$fuzzer.cc .
    $CXX fuzz_$fuzzer.cc -o $OUT/fuzz_$fuzzer $CXXFLAGS $LIB_FUZZING_ENGINE \
      ./xpdf/libtestXpdfStatic.a ./fofi/libfofi.a ./goo/libgoo.a \
      -I../ -I../goo -I../fofi -I. -I../xpdf
done

# Copy over options files
cp $SRC/fuzz_pdfload.options $OUT/
