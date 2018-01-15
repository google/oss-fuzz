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

# configure script needs leak checking disabled to not fail
export ASAN_OPTIONS=detect_leaks=0
./autogen.sh
./configure --with-perl=no --disable-shared --without-textui --with-fuzzer \
	--with-fuzzer-lib=$LIB_FUZZING_ENGINE \
	CC=$CC CXX=$CXX PKG_CONFIG="pkg-config --static"
make clean
make "-j$(nproc)" CFLAGS="-static -DSUPPRESS_PRINTF_FALLBACK $CFLAGS" CXXFLAGS="-static $CXXFLAGS"

# now build irssi-fuzz itself

export GLIB_CFLAGS="$(pkg-config --static --cflags glib-2.0)"
export GLIB_LIBS="$(pkg-config --static --libs glib-2.0)"

CORE_LIBS="src/core/libcore.a"
CORE_LIBS="$CORE_LIBS src/lib-config/libirssi_config.a"

FE_COMMON_LIBS="src/irc/libirc.a"
FE_COMMON_LIBS="$FE_COMMON_LIBS src/irc/core/libirc_core.a"
FE_COMMON_LIBS="$FE_COMMON_LIBS src/fe-common/irc/libfe_common_irc.a"
FE_COMMON_LIBS="$FE_COMMON_LIBS src/fe-common/core/libfe_common_core.a"

FE_FUZZ_CFLAGS="-I. -Isrc -Isrc/core/ -Isrc/irc/core/ -Isrc/fe-common/core/"

${CXX} ${CXXFLAGS} -DHAVE_CONFIG_H -lFuzzingEngine ${FE_FUZZ_CFLAGS} ${GLIB_CFLAGS} \
	src/fe-fuzz/irssi.o src/fe-fuzz/module-formats.o -lm \
	-Wl,-Bstatic ${FE_COMMON_LIBS} ${CORE_LIBS} -lssl -lcrypto ${GLIB_LIBS} -lgmodule-2.0 -lz \
	-Wl,-Bdynamic -o $OUT/irssi-fuzz

# now build event-get-params-fuzz

${CXX} ${CXXFLAGS} -DHAVE_CONFIG_H -lFuzzingEngine ${FE_FUZZ_CFLAGS} ${GLIB_CFLAGS} \
	src/fe-fuzz/irc/core/event-get-params.o src/fe-fuzz/module-formats.o -lm \
	-Wl,-Bstatic ${FE_COMMON_LIBS} ${CORE_LIBS} -lssl -lcrypto ${GLIB_LIBS} -lgmodule-2.0 -lz \
	-Wl,-Bdynamic -o $OUT/event-get-params-fuzz

cp $SRC/*.options $OUT/
