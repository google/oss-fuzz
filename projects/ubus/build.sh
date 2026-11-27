#!/bin/bash -eu
# Copyright 2026 Google LLC
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

PREFIX=/src/install

# Build json-c
cd /src/json-c
cmake \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DBUILD_SHARED_LIBS=OFF \
    -DDISABLE_EXTRA_LIBS=ON \
    -DBUILD_TESTING=OFF \
    -B build -S .
cmake --build build -j$(nproc)
cmake --install build

# Build libubox
cd /src/libubox
cmake \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_PREFIX_PATH="${PREFIX}" \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DBUILD_LUA=OFF \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_STATIC=ON \
    -B build -S .
cmake --build build -j$(nproc)
cmake --install build

# Build ubus static libraries
cd /src/ubus
cmake \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_PREFIX_PATH="${PREFIX}" \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DBUILD_LUA=OFF \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_STATIC=ON \
    -B build -S .
cmake --build build -j$(nproc)

# Build fuzz targets
for fuzzer_src in /src/ubus/tests/fuzz/test-*.c; do
    fuzzer_name=$(basename "${fuzzer_src}" .c)

    "${CC}" ${CFLAGS} \
        -I/src/ubus \
        -I"${PREFIX}/include" \
        -c "${fuzzer_src}" \
        -o "/tmp/${fuzzer_name}.o"

    "${CXX}" ${CXXFLAGS} \
        "/tmp/${fuzzer_name}.o" \
        ${LIB_FUZZING_ENGINE} \
        /src/ubus/build/libubus.a \
        /src/ubus/build/libubusd_library.a \
        "${PREFIX}/lib/libubox.a" \
        "${PREFIX}/lib/libblobmsg_json.a" \
        "${PREFIX}/lib/libjson-c.a" \
        -o "${OUT}/${fuzzer_name}"

    # Package seed corpus if it exists
    if [ -d /src/ubus/tests/fuzz/corpus ]; then
        zip -j "${OUT}/${fuzzer_name}_seed_corpus.zip" /src/ubus/tests/fuzz/corpus/*
    fi
done
