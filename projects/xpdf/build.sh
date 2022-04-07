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

PREFIX=$WORK/prefix
mkdir -p $PREFIX

export PKG_CONFIG="`which pkg-config` --static"
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
export PATH=$PREFIX/bin:$PATH
pushd $SRC/freetype
./autogen.sh
./configure --prefix="$PREFIX" --disable-shared PKG_CONFIG_PATH="$PKG_CONFIG_PATH" --with-png=no --with-zlib=no 
make -j$(nproc)
make install
popd

# Make minor change in the CMakeFiles file.
sed -i 's/#--- object files needed by XpdfWidget/add_library(testXpdfStatic STATIC $<TARGET_OBJECTS:xpdf_objs>)\n#--- object files needed by XpdfWidget/' ./xpdf/CMakeLists.txt
sed -i 's/#--- pdftops/add_library(testXpdfWidgetStatic STATIC $<TARGET_OBJECTS:xpdf_widget_objs>\n $<TARGET_OBJECTS:splash_objs>\n $<TARGET_OBJECTS:xpdf_objs>\n ${FREETYPE_LIBRARY}\n ${FREETYPE_OTHER_LIBS})\n#--- pdftops/' ./xpdf/CMakeLists.txt

# Build the project
mkdir build && cd build
export LD=$CXX
cmake ../ -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DOPI_SUPPORT=ON -DSPLASH_CMYK=ON -DMULTITHREADED=ON \
  -DUSE_EXCEPTIONS=ON -DXPDFWIDGET_PRINTING=ON -DFREETYPE_DIR="$PREFIX"
make

# Build fuzzers
for fuzzer in zxdoc pdfload JBIG2; do
    cp ../../fuzz_$fuzzer.cc .
    $CXX fuzz_$fuzzer.cc -o $OUT/fuzz_$fuzzer $CXXFLAGS $LIB_FUZZING_ENGINE \
      ./xpdf/libtestXpdfStatic.a ./fofi/libfofi.a ./goo/libgoo.a ./splash/libsplash.a ./xpdf/libtestXpdfWidgetStatic.a /work/prefix/lib/libfreetype.a \
      -I../ -I../goo -I../fofi -I. -I../xpdf -I../splash
done

# Copy over options files
cp $SRC/fuzz_pdfload.options $OUT/
