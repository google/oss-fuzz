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
#While Compiling the dependency, I do not want sanitizers or the fuzzing tags in the dependency library.
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
-DCMAKE_C_COMPILER="clang" -DCMAKE_CXX_COMPILER="clang++" \
-DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ../
make -j$(nproc)
make install
popd


#Build MapServer
cd $SRC/MapServer
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_STATIC=ON \
-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
-DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
-DWITH_PROTOBUFC=0 -DWITH_FRIBIDI=0 -DWITH_HARFBUZZ=0 -DWITH_CAIRO=0 -DWITH_FCGI=0 \
-DWITH_GEOS=0 -DWITH_POSTGIS=0 -DWITH_GIF=0 ../
#While using undefined sanitizer, Project cannot compile binary but can compile library.
make -j$(nproc) --ignore-errors 


#Fuzzer
cp ../fuzzers/*.c .

$CC $CFLAGS -Wall -Wextra -I. -I/usr/include/gdal/. -DPROJ_VERSION_MAJOR=6 -c mapfuzzer.c
$CC $CFLAGS -Wall -Wextra -I. -I/usr/include/gdal/. -DPROJ_VERSION_MAJOR=6 -c shapefuzzer.c

$CXX $CFLAGS $LIB_FUZZING_ENGINE mapfuzzer.o -o mapfuzzer \
-L. -lmapserver_static -lgdal \
-l:libpng.a -l:libjpeg.a -l:libfreetype.a -l:libproj.a -l:libxml2.a -l:libz.a \
-l:libicuuc.a -l:libicudata.a -l:libsqlite3.a -l:liblzma.so.5 -lc++

$CXX $CFLAGS $LIB_FUZZING_ENGINE shapefuzzer.o -o shapefuzzer \
-L. -lmapserver_static -lgdal \
-l:libpng.a -l:libjpeg.a -l:libfreetype.a -l:libproj.a -l:libxml2.a -l:libz.a \
-l:libicuuc.a -l:libicudata.a -l:libsqlite3.a -l:liblzma.so.5 -lc++


#SetUp
cp mapfuzzer $OUT/mapfuzzer
cp shapefuzzer $OUT/shapefuzzer

cd ../
zip -r $OUT/mapfuzzer_seed_corpus.zip tests/*.map
zip -r $OUT/shapefuzzer_seed_corpus.zip tests/*.shp tests/*.shx tests/*.dbf
