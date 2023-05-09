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

# Disable code instrumentation
CFLAGS_SAVE="$CFLAGS"
CXXFLAGS_SAVE="$CXXFLAGS"
unset CFLAGS
unset CXXFLAGS
export AFL_NOOPT=1
# This is needed because oss-fuzz always uses it
export CXXFLAGS="-stdlib=libc++"

### Dependencies that need static linking ###

# libpcap
cd $SRC/libpcap-1.9.1
./configure --disable-shared
make -j$(nproc)
make install

# zeromq
cd $SRC/zeromq-4.3.4
./autogen.sh
./configure --without-documentation --without-libsodium --enable-static --disable-shared
make -j$(nproc)
make install

# json-c
cd $SRC/json-c-json-c-0.16-20220414
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF ..
make -j$(nproc)
make install

# libmaxminddb
cd $SRC/libmaxminddb-1.7.1
./configure --disable-shared --enable-static
make -j$(nproc)
make install


### ntopng dependecies ###

# Build nDPI
cd $NDPI_HOME
./autogen.sh
make -j$(nproc)

# Build LUA
make -C $NTOPNG_HOME/third-party/lua-5.4.3 generic

# Build librrdtool
cd $NTOPNG_HOME/third-party/rrdtool-1.4.8
./configure --disable-libdbi --disable-libwrap --disable-rrdcgi --disable-libtool-lock \
    --disable-nls --disable-rpath --disable-perl --disable-ruby --disable-lua \
    --disable-tcl --disable-python --disable-dependency-tracking --disable-rrd_graph
cd src
make librrd_th.la


# Re-enable code instrumentation
export CFLAGS="${CFLAGS_SAVE}"
export CXXFLAGS="${CXXFLAGS_SAVE}"
unset AFL_NOOPT

### Build ntopng ###

cd $NTOPNG_HOME

./autogen.sh

./configure --enable-fuzztargets --without-hiredis --with-zmq-static \
    --with-json-c-static --with-maxminddb-static

make -j$(nproc) fuzz_all

# Copy fuzzers
find fuzz/ -regex 'fuzz/fuzz_[a-z_]*' -exec cp {} {}.dict {}_seed_corpus.zip $OUT/ \;

# Create the directory structure needed for fuzzing
mkdir -p $OUT/install $OUT/data-dir $OUT/docs $OUT/scripts/callbacks