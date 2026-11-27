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

# Build libcbor
pushd libcbor
cmake -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j"$(nproc)"
make install
popd

git checkout devel

mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_TOOLS=OFF ..
make

static_pcre=($(find /usr/lib -name "libpcre2-8.a" 2>/dev/null))
static_cbor=($(find /usr/local -name "libcbor.a" 2>/dev/null))

# Static builds force ENABLE_TESTS=OFF, so tests/CMakeLists.txt never runs
# configure_file() and tests_config.h is not generated. Reproduce that call
# (ESCAPE_QUOTES @ONLY) so TESTS_SRC points at the tests/ source tree.
mkdir -p tests
cmake -DPROJECT_SOURCE_DIR="${SRC}/libyang" \
    -DPROJECT_BINARY_DIR="${SRC}/libyang/build" \
    -P "${SRC}/libyang_tests_config.cmake"

cp -r "$SRC/libyang/modules" "$OUT/modules"
printf '#define TESTS_SRC "/out/modules"\n#define TESTS_BIN "%s"\n' \
    "$SRC/libyang/build" > tests/tests_config.h

for fuzzer in lys_parse_mem lyd_parse_mem_xml lyd_parse_mem_json lyd_parse_lyb \
    lyd_parse_schema_mount_xml yang_parse_module lys_parse_mem_yin lyd_eval_xpath \
    lyd_lyb_roundtrip lyd_cbor_roundtrip; do
  $CC $CFLAGS -c ../tests/fuzz/${fuzzer}.c -I./libyang -I./compat -I./tests
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE ${fuzzer}.o -o $OUT/${fuzzer} \
    ./libyang.a ${static_pcre} ${static_cbor}

  if [[ -f ../tests/fuzz/${fuzzer}.dict ]]; then
    cp ../tests/fuzz/${fuzzer}.dict $OUT/
  fi

  if [[ -d ../tests/fuzz/corpus/${fuzzer} ]]; then
    find ../tests/fuzz/corpus/${fuzzer} -type f -exec \
      zip -qj $OUT/${fuzzer}_seed_corpus.zip {} +
  fi
done

# Build test
mkdir $SRC/libyang/build-test
cd $SRC/libyang/build-test
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
