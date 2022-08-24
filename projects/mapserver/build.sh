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
mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_STATIC=ON \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$CFLAGS" -DCMAKE_SHARED_LINKER_FLAGS="$CFLAGS" ../

make -j$(nproc)

#Fuzzer
cp ../fuzzers/*.c .

$CC $CFLAGS -Wall -Wextra -I. -I/usr/include/gdal/. -DPROJ_VERSION_MAJOR=6 -c mapfuzzer.c
$CC $CFLAGS -Wall -Wextra -I. -I/usr/include/gdal/. -DPROJ_VERSION_MAJOR=6 -c shapefuzzer.c

$CXX $CFLAGS $LIB_FUZZING_ENGINE mapfuzzer.o -o mapfuzzer \
-L. -lmapserver_static \
-lgdal -lgeos_c -lgif -ljpeg -lpng -lpq -lproj -lxml2 -lfreetype -lcairo -lfribidi -lharfbuzz -lprotobuf-c

$CXX $CFLAGS $LIB_FUZZING_ENGINE shapefuzzer.o -o shapefuzzer \
-L. -lmapserver_static \
-lgdal -lgeos_c -lgif -ljpeg -lpng -lpq -lproj -lxml2 -lfreetype -lcairo -lfribidi -lharfbuzz -lprotobuf-c

#SetUp
cp mapfuzzer $OUT/mapfuzzer
cp shapefuzzer $OUT/shapefuzzer

cd ../
zip -r $OUT/mapfuzzer_seed_corpus.zip tests/*.map
zip -r $OUT/shapefuzzer_seed_corpus.zip tests/*.shp tests/*.shx tests/*.dbf

#CopyLibrary
mkdir -p $OUT/lib

cd /lib/
cp libarmadillo.so.9 libdfalt.so.0 libgdal.so.26 libmfhdfalt.so.0 libogdi.so.4.1 $OUT/lib

cd /lib/x86_64-linux-gnu/
cp libaec.so.0 libarpack.so.2 libblas.so.3 libcairo.so.2 libcfitsio.so.8 libCharLS.so.2 libdap.so.25 libxml2.so.2 \
libdapclient.so.6 libepsilon.so.1 libfontconfig.so.1 libfreetype.so.6 libfreexl.so.1 libfribidi.so.0 \
libfyba.so.0 libfygm.so.0 libfyut.so.0 libgeos_c.so.1 libgeos-3.8.0.so libgeotiff.so.5 libgfortran.so.5 \
libgif.so.7 libgraphite2.so.3 libharfbuzz.so.0 libhdf5_serial_hl.so.100 libhdf5_serial.so.103 libjbig.so.0 \
libjpeg.so.8 libkmlbase.so.1 libkmldom.so.1 libkmlengine.so.1 liblapack.so.3 liblcms2.so.2 libltdl.so.7 \
libminizip.so.1 libmysqlclient.so.21 libnetcdf.so.15 libnspr4.so libnss3.so libnssutil3.so libodbc.so.2 \
libodbcinst.so.2 libopenjp2.so.7 libpixman-1.so.0 libplc4.so libplds4.so libpng16.so.16 libpoppler.so.97 \
libpq.so.5 libproj.so.15 libprotobuf-c.so.1 libqhull.so.7 libsmime3.so libspatialite.so.7 libsuperlu.so.5 \
libsz.so.2 libtiff.so.5 liburiparser.so.1 libwebp.so.6 libxcb-render.so.0 libxcb-shm.so.0 libxerces-c-3.2.so \
libXrender.so.1 $OUT/lib

#patchelf
patchelf --set-rpath '$ORIGIN/lib' $OUT/mapfuzzer
patchelf --set-rpath '$ORIGIN/lib' $OUT/shapefuzzer
