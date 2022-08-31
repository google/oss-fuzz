#!/bin/bash -eu
# Copyright 2022 Google LLC
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
#Build gdal dependency
pushd $SRC/gdal
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
-DCMAKE_C_FLAGS="$CFLAGS -fPIC" -DCMAKE_CXX_FLAGS="$CXXFLAGS -fPIC" ../
make -j$(nproc)
make install
popd

#Build MapServer
cd $SRC/MapServer
mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_STATIC=ON \
-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
-DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CFLAGS" \
-DCMAKE_EXE_LINKER_FLAGS="$CFLAGS" -DCMAKE_SHARED_LINKER_FLAGS="$CFLAGS" \
-DWITH_PROTOBUFC=0 -DWITH_FRIBIDI=0 -DWITH_HARFBUZZ=0 -DWITH_CAIRO=0 -DWITH_FCGI=0 \
-DWITH_GEOS=0 -DWITH_POSTGIS=0 -DWITH_GIF=0 ../
make -j$(nproc)

#Fuzzer
cp ../fuzzers/*.c .

$CC $CFLAGS -Wall -Wextra -I. -I/usr/include/gdal/. -DPROJ_VERSION_MAJOR=6 -c mapfuzzer.c
$CC $CFLAGS -Wall -Wextra -I. -I/usr/include/gdal/. -DPROJ_VERSION_MAJOR=6 -c shapefuzzer.c

$CXX $CFLAGS $LIB_FUZZING_ENGINE mapfuzzer.o -o mapfuzzer \
-L. -lmapserver_static -lgdal \
/usr/lib/x86_64-linux-gnu/libpng.a \
/usr/lib/x86_64-linux-gnu/libjpeg.a \
/usr/lib/x86_64-linux-gnu/libproj.a \
/usr/lib/x86_64-linux-gnu/libsqlite3.a \
/usr/lib/x86_64-linux-gnu/libfreetype.a \
/lib/x86_64-linux-gnu/libxml2.a \
/lib/x86_64-linux-gnu/libicuuc.a \
/lib/x86_64-linux-gnu/libicudata.a \
/usr/lib/x86_64-linux-gnu/libz.a \
/lib/x86_64-linux-gnu/liblzma.so.5 

$CXX $CFLAGS $LIB_FUZZING_ENGINE shapefuzzer.o -o shapefuzzer \
-L. -lmapserver_static -lgdal \
/usr/lib/x86_64-linux-gnu/libpng.a \
/usr/lib/x86_64-linux-gnu/libjpeg.a \
/usr/lib/x86_64-linux-gnu/libproj.a \
/usr/lib/x86_64-linux-gnu/libsqlite3.a \
/usr/lib/x86_64-linux-gnu/libfreetype.a \
/lib/x86_64-linux-gnu/libxml2.a \
/lib/x86_64-linux-gnu/libicuuc.a \
/lib/x86_64-linux-gnu/libicudata.a \
/usr/lib/x86_64-linux-gnu/libz.a \
/lib/x86_64-linux-gnu/liblzma.so.5 

#SetUp
cp mapfuzzer $OUT/mapfuzzer
cp shapefuzzer $OUT/shapefuzzer

cd ../
zip -r $OUT/mapfuzzer_seed_corpus.zip tests/*.map
zip -r $OUT/shapefuzzer_seed_corpus.zip tests/*.shp tests/*.shx tests/*.dbf
