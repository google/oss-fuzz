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

# For coverage build we need to remove some flags when building icu
if [ "$SANITIZER" = "coverage" ]
then
    export OCX=$CXXFLAGS
    export OC=$CFLAGS
    CF1=${CFLAGS//-fprofile-instr-generate/}
    export CFLAGS=${CF1//-fcoverage-mapping/}
    CXF1=${CXXFLAGS//-fprofile-instr-generate/}
    export CXXFLAGS=${CXF1//-fcoverage-mapping/}
fi

# Build icu
export DEPS_PATH=/src/deps/
mkdir $DEPS_PATH

# build ICU for linking statically.
cd $SRC/icu/source
./configure --disable-shared --enable-static --disable-layoutex \
  --disable-tests --disable-samples --with-data-packaging=static --prefix=$DEPS_PATH
make install -j$(nproc)

# Ugly ugly hack to get static linking to work for icu.
cd $DEPS_PATH/lib
ls *.a | xargs -n1 ar x
rm *.a
ar r libicu.a *.{ao,o}
ln -s libicu.a libicudata.a
ln -s libicu.a libicuuc.a
ln -s libicu.a libicui18n.a

if [ "$SANITIZER" = "coverage" ]
then
    export CFLAGS=$OC
    export CXXFLAGS=$OCX
fi

# Build glib ourselves in order to compile statically
cd /
git clone --depth 1 https://gitlab.gnome.org/GNOME/glib
cd glib
mkdir build
meson ./build \
  -Db_lundef=false \
  -Ddefault_library=static \
  -Dlibmount=disabled
ninja -C ./build

cd $SRC/fontforge
sed -i 's/add_subdirectory(fontforgeexe)/#add_subdirectory(fontforgeexe)/g' ./CMakeLists.txt

mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=OFF  \
    -DENABLE_LIBSPIRO=OFF \
    -DENABLE_LIBUNINAMESLIST=OFF \
    -DENABLE_LIBGIF=OFF \
    -DENABLE_LIBJPEG=OFF \
    -DENABLE_LIBPNG=OFF \
    -DENABLE_LIBREADLINE=OFF \
    -DENABLE_LIBTIFF=OFF \
    -DENABLE_WOFF2=OFF \
    -DENABLE_DOCS=OFF \
    -DENABLE_PYTHON_EXTENSION=OFF \
    -DENABLE_PYTHON_SCRIPTING=OFF \
    -DENABLE_NATIVE_SCRIPTING=OFF \
    -DENABLE_GUI=OFF ..
make 

# Compile and link the fuzzer to all the necessary libraries.
LIBS="/usr/lib/x86_64-linux-gnu"
LIBICU=/src/deps/lib
GLIBS="/glib/build"
$CC $CFLAGS -c $SRC/fuzz_pdf.c
$CXX -v $CXXFLAGS $LIB_FUZZING_ENGINE  \
    ./fuzz_pdf.o -o $OUT/fuzz_pdf ./lib/libfontforge.a \
    -Wl,--start-group \
            ${GLIBS}/gmodule/libgmodule-2.0.a \
            ${GLIBS}/glib/libglib-2.0.a \
            ${GLIBS}/gio/libgio-2.0.a \
            ${GLIBS}/gobject/libgobject-2.0.a \
            ${LIBICU}/libicudata.a \
            ${LIBICU}/libicuuc.a \
            -lm -pthread -lresolv   -lpcre -lpthread -lrt  \
            -lz -lselinux -llzma -l:libpng.a -l:libffi.a \
            -l:libtiff.a -l:libxml2.a -l:libfreetype.a \
     -Wl,--end-group
