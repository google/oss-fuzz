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

if [ -f .gitmodules ]; then
  sed -i 's/git@/https:\/\//g' .gitmodules
  sed -i 's/:taos/\/taos/g' .gitmodules
  sed -i 's/\.git//g' .gitmodules
  git submodule update --init --recursive
fi
sed -i 's/-Werror[^ ]*//g' ./cmake/define.cmake
# Suppress deprecated literal operator warning in geos external dependency
sed -i 's|-DBUILD_GEOSOP:BOOL=OFF|-DBUILD_GEOSOP:BOOL=OFF\n        CMAKE_ARGS -DCMAKE_CXX_FLAGS=-Wno-deprecated-literal-operator|' ./cmake/external.cmake
# Fix clang incompatibility: void** is not a valid target for bitwise atomic ops
# (newer clang requires integer pointer types). Cast to size_t* like Darwin branch.
sed -i 's/__atomic_and_fetch((void\*\*)(ptr), (val)/__atomic_and_fetch((size_t*)(ptr), (size_t)(val)/g' ./source/os/src/osAtomic.c
sed -i 's/__atomic_fetch_and((void\*\*)(ptr), (val)/__atomic_fetch_and((size_t*)(ptr), (size_t)(val)/g' ./source/os/src/osAtomic.c
sed -i 's/__atomic_or_fetch((void\*\*)(ptr), (val)/__atomic_or_fetch((size_t*)(ptr), (size_t)(val)/g' ./source/os/src/osAtomic.c
sed -i 's/__atomic_fetch_or((void\*\*)(ptr), (val)/__atomic_fetch_or((size_t*)(ptr), (size_t)(val)/g' ./source/os/src/osAtomic.c
sed -i 's/__atomic_xor_fetch((void\*\*)(ptr), (val)/__atomic_xor_fetch((size_t*)(ptr), (size_t)(val)/g' ./source/os/src/osAtomic.c
sed -i 's/__atomic_fetch_xor((void\*\*)(ptr), (val)/__atomic_fetch_xor((size_t*)(ptr), (size_t)(val)/g' ./source/os/src/osAtomic.c
mkdir debug && cd debug
export LDFLAGS="${CXXFLAGS}"

if [[ $SANITIZER = *coverage* ]]; then
  ln -f -s /usr/bin/gold /usr/bin/ld
fi

cmake -DBUILD_HTTP=true -DBUILD_TEST=false ..
# Build parser and all libraries it depends on at link time
cmake --build . --target parser nodes catalog function scalar -- -j$(nproc)

# Short-hand base directories
TDENGINE_SRC=/src/tdengine
BUILDLIB=${TDENGINE_SRC}/debug/build/lib
EXTLIB=${TDENGINE_SRC}/.externals/install

# Compile the fuzzer harness
$CC $CFLAGS \
     -I${TDENGINE_SRC}/include/libs/parser \
     -I${TDENGINE_SRC}/include/libs/nodes \
     -I${TDENGINE_SRC}/include/libs/catalog \
     -I${TDENGINE_SRC}/include/libs/qcom \
     -I${TDENGINE_SRC}/include/libs/transport \
     -I${TDENGINE_SRC}/include/libs/scalar \
     -I${TDENGINE_SRC}/include/libs/function \
     -I${TDENGINE_SRC}/include/libs/decimal \
     -I${TDENGINE_SRC}/include/common \
     -I${TDENGINE_SRC}/include/util \
     -I${TDENGINE_SRC}/include/os \
     -I${TDENGINE_SRC}/include/client \
     -o sql-fuzzer.o -c $SRC/sql-fuzzer.c

# Link the fuzzer against the parser and all transitive dependencies
$CC $CFLAGS $LIB_FUZZING_ENGINE sql-fuzzer.o -o $OUT/sql-fuzzer \
     -Wl,--start-group \
     ${BUILDLIB}/libparser.a \
     ${BUILDLIB}/libplanner.a \
     ${BUILDLIB}/libcatalog.a \
     ${BUILDLIB}/libfunction.a \
     ${BUILDLIB}/libscalar.a \
     ${BUILDLIB}/libnodes.a \
     ${BUILDLIB}/libqcom.a \
     ${BUILDLIB}/libtransport.a \
     ${BUILDLIB}/libgeometry.a \
     ${BUILDLIB}/libutil.a \
     ${BUILDLIB}/libcommon.a \
     ${BUILDLIB}/libos.a \
     ${BUILDLIB}/libdecimal.a \
     ${BUILDLIB}/libwideInteger.a \
     ${BUILDLIB}/libTSZ.a \
     ${BUILDLIB}/libaes.a \
     ${BUILDLIB}/libsm4.a \
     ${BUILDLIB}/libcrypt.a \
     ${BUILDLIB}/libtotp.a \
     ${EXTLIB}/ext_geos/Debug/lib/libgeos_c.a \
     ${EXTLIB}/ext_geos/Debug/lib/libgeos.a \
     ${EXTLIB}/ext_lz4/Debug/lib/liblz4.a \
     ${EXTLIB}/ext_ssl/Debug/lib/libssl.a \
     ${EXTLIB}/ext_ssl/Debug/lib/libcrypto.a \
     ${EXTLIB}/ext_zlib/Debug/lib/libz.a \
     ${EXTLIB}/ext_xxhash/Debug/usr/local/lib/libxxhash.a \
     ${EXTLIB}/ext_tz/Debug/usr/lib/libtz.a \
     ${EXTLIB}/ext_cjson/Debug/lib/libcjson.a \
     ${EXTLIB}/ext_pcre2/Debug/lib/libpcre2-8.a \
     ${EXTLIB}/ext_lzma2/Debug/usr/local/lib/libfast-lzma2.a \
     ${EXTLIB}/ext_libuv/Debug/lib/libuv.a \
     ${EXTLIB}/ext_curl/Debug/lib/libcurl.a \
     -Wl,--end-group -lpthread -ldl -lm -lstdc++

cp $SRC/*.options $OUT/
