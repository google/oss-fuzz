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

pushd $SRC/ogg
./autogen.sh
./configure --prefix="$WORK" --enable-static --disable-shared --disable-crc
make clean
make -j$(nproc)
make install
popd

pushd $SRC/vorbis
./autogen.sh
./configure --prefix="$WORK" --enable-static --disable-shared
make clean
make -j$(nproc)
make install
popd


pushd $SRC/libsndfile
./autogen.sh
./configure --disable-shared --enable-ossfuzzers
make -j$(nproc)
popd



cd $SRC/openal/build
cmake -DLIBTYPE=STATIC -DLSOFT_EXAMPLES:BOOL=ON \
	-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON ..
make V=1 -j$(nproc)

$CC $CFLAGS -DAL_LIBTYPE_STATIC -DRESTRICT=__restrict -I/src/openal/common \
	-I/src/openal/include  -I/src/libsndfile/include -I/src/openal/examples \
	-O2 -g -D_DEBUG -fvisibility=hidden -pthread -o fuzzer.o -c /src/fuzzer.c

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.o -o $OUT/fuzzer \
	/src/openal/build/libex-common.a /src/openal/build/libopenal.a \
	/src/libsndfile/src/.libs/libsndfile.a \
	/src/libsndfile/src/.libs/libcommon.a \
	/src/vorbis/lib/.libs/libvorbisenc.a \
	/src/vorbis/lib/.libs/libvorbis.a \
	/src/vorbis/lib/.libs/libvorbisfile.a \
	/src/ogg/src/.libs/libogg.a
