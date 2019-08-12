#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

I386_PACKAGES="zlib1g-dev:i386 libexpat-dev:i386 liblzma-dev:i386 \
              libxerces-c-dev:i386 libpng12-dev:i386 libgif-dev:i386 \
              libwebp-dev:i386 libicu-dev:i386 libnetcdf-dev:i386 \
              libssl-dev:i386 libsqlite3-dev:i386"
X64_PACKAGES="zlib1g-dev libexpat-dev liblzma-dev \
              libxerces-c-dev libpng12-dev libgif-dev \
              libwebp-dev libicu-dev libnetcdf-dev \
              libssl-dev libsqlite3-dev"

if [ "$ARCHITECTURE" = "i386" ]; then
    apt-get install -y $I386_PACKAGES automake libtool autoconf
else
    apt-get install -y $X64_PACKAGES
fi


# build libproj.a (proj master required)
cd proj
./autogen.sh
SQLITE3_CFLAGS=-I/usr/include SQLITE3_LIBS=-lsqlite3 ./configure --disable-shared --prefix=$SRC/install
make clean -s
make -j$(nproc) -s
make install
cd ..

# build libcurl.a (builing against Ubuntu libcurl.a doesn't work easily)
cd curl
./buildconf
./configure --disable-shared --prefix=$SRC/install
make clean -s
make -j$(nproc) -s
make install
cd ..

# build libnetcdf.a
cd netcdf-4.4.1.1
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=$SRC/install -DHDF5_C_LIBRARY=libhdf5_serial.a -DHDF5_HL_LIBRARY=libhdf5_serial_hl.a -DHDF5_INCLUDE_DIR=/usr/include/hdf5/serial -DENABLE_DAP:BOOL=OFF -DBUILD_SHARED_LIBS:BOOL=OFF -DBUILD_UTILITIES:BOOL=OFF -DBUILD_TESTING:BOOL=OFF -DENABLE_TESTS:BOOL=OFF
make clean -s
make -j$(nproc) -s
make install
cd ../..

# build gdal
cd gdal
export LDFLAGS=${CXXFLAGS}
./configure --without-libtool --with-liblzma --with-expat --with-sqlite3 --with-xerces --with-webp --with-netcdf=$SRC/install --with-curl=$SRC/install/bin/curl-config --without-hdf5 --with-jpeg=internal --with-proj=$SRC/install
make clean -s
make -j$(nproc) -s static-lib

export EXTRA_LIBS="-Wl,-Bstatic -lproj -lwebp -llzma -lexpat -lsqlite3 -lgif -lpng12 -lz"
# Xerces-C related
export EXTRA_LIBS="$EXTRA_LIBS -lxerces-c -licuuc -licudata"
# netCDF related
export EXTRA_LIBS="$EXTRA_LIBS -L$SRC/install/lib -lnetcdf -lhdf5_serial_hl -lhdf5_serial -lsz -laec -lz"
# curl related
export EXTRA_LIBS="$EXTRA_LIBS -L$SRC/install/lib -lcurl -lssl -lcrypto -lz"
export EXTRA_LIBS="$EXTRA_LIBS -Wl,-Bdynamic -ldl -lpthread"
./fuzzers/build_google_oss_fuzzers.sh
./fuzzers/build_seed_corpus.sh
