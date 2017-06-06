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


curl ftp://ftp.unidata.ucar.edu/pub/netcdf/netcdf-4.4.1.1.tar.gz > netcdf-4.4.1.1.tar.gz
tar xvzf netcdf-4.4.1.1.tar.gz
cd netcdf-4.4.1.1
./configure --enable-static --disable-netcdf-4 --disable-dap --prefix=$SRC/install
make clean -s
make -j$(nproc) -s
make install
cd ..

# build gdal
cd gdal
export LDFLAGS=${CXXFLAGS}
./configure --without-libtool --with-liblzma --with-expat --with-sqlite3 --with-xerces --with-webp --with-netcdf=$SRC/install --without-curl --without-hdf5 --with-jpeg=internal
make clean -s
make -j$(nproc) -s

export EXTRA_LIBS="-Wl,-Bstatic -lwebp -llzma -lexpat -lsqlite3 -lgif -lpng12 -lz"
# Xerces-C related
export EXTRA_LIBS="$EXTRA_LIBS -lxerces-c -licuuc -licudata"
# netCDF related
export EXTRA_LIBS="$EXTRA_LIBS -L$SRC/install/lib -lnetcdf"
export EXTRA_LIBS="$EXTRA_LIBS -Wl,-Bdynamic -ldl -lpthread"
./fuzzers/build_google_oss_fuzzers.sh
./fuzzers/build_seed_corpus.sh
