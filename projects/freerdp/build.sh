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

# Avoid compilation issue due to some undefined references. They are defined in
# libc++ and used by Centipede so -lc++ needs to come after centipede's lib.
if [[ $FUZZING_ENGINE == centipede ]]
then
    sed -i \
        '/$ENV{LIB_FUZZING_ENGINE}/a \ \ \ \ \ \ \ \ -lc++' \
        cmake/ConfigOptions.cmake
fi

case $SANITIZER in
  address) SANITIZERS_ARGS="-DWITH_SANITIZE_ADDRESS=ON" ;;
  memory) SANITIZERS_ARGS="-DWITH_SANITIZE_MEMORY=ON" ;;
  *) SANITIZERS_ARGS="" ;;
esac

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    # clang-15 segfaults on linking binaries when LTO is enabled,
    # see https://github.com/google/oss-fuzz/pull/10448#issuecomment-1578160436
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF

    $SANITIZERS_ARGS

    -DCMAKE_BUILD_TYPE=Debug
    -DBUILD_SHARED_LIBS=OFF

    # LOCAL-ONLY: base-builder (focal) ships jansson 2.12 (< required 2.13)
    # and json-c 0.13 (missing json_object_new_uint64), so winpr/json fails
    # to compile. JSON is unused by the fuzz targets; disable it to build
    # locally. (Upstream/production uses a newer base image.)
    -DWITH_JSON_DISABLED=ON

    # C compiler
    -DCMAKE_C_COMPILER="${CC}"
    -DCMAKE_C_FLAGS="${CFLAGS}"

    # C++ compiler
    -DCMAKE_CXX_COMPILER="${CXX}"
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}"

    # Linker
    -DCMAKE_LINKER="${LD}"
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)

# Build the project and fuzzers.
rm -rf build
cmake "${cmake_args[@]}" -S . -B build -G Ninja -C ci/cmake-preloads/config-oss-fuzz.cmake
cmake --build build --parallel --target fuzzers TestFuzzServerSeedGen

for f in $(find build/Testing/ -name 'TestFuzz*' ! -name 'TestFuzzServerSeedGen' -type f);
do
    cp $f $OUT/
done

# Generate the seed corpus for TestFuzzServer and package it as
# $OUT/TestFuzzServer_seed_corpus.zip.
mkdir -p $WORK/TestFuzzServer_corpus/input $WORK/TestFuzzServer_corpus/noinput $WORK/TestFuzzServer_corpus/stage
# With post-connect input PDUs:
./build/Testing/TestFuzzServerSeedGen $WORK/TestFuzzServer_corpus/input 1
# Handshake only:
./build/Testing/TestFuzzServerSeedGen $WORK/TestFuzzServer_corpus/noinput 0
cp $WORK/TestFuzzServer_corpus/input/handshake $WORK/TestFuzzServer_corpus/stage/handshake_input
cp $WORK/TestFuzzServer_corpus/noinput/handshake $WORK/TestFuzzServer_corpus/stage/handshake_noinput
cp $WORK/TestFuzzServer_corpus/input/handshake_cut* $WORK/TestFuzzServer_corpus/stage/
zip --junk-paths --quiet $OUT/TestFuzzServer_seed_corpus.zip $WORK/TestFuzzServer_corpus/stage/*

# TestFuzzCodecs seed corpus: valid RemoteFX bitstreams (RLGR1/RLGR3 tiles) that
# reach the tile-decode subsystem (rfx_rlgr.c, rfx_decode.c, sse/rfx_sse2.c) the
# mutation-only corpus never reaches. generate_seeds.py has no FreeRDP deps.
rm -rf $WORK/TestFuzzCodecs_corpus $OUT/TestFuzzCodecs_seed_corpus.zip
mkdir -p $WORK/TestFuzzCodecs_corpus
python3 $SRC/generate_seeds.py $WORK/TestFuzzCodecs_corpus
if [ -n "$(ls -A $WORK/TestFuzzCodecs_corpus 2>/dev/null)" ]; then
    zip --junk-paths --quiet $OUT/TestFuzzCodecs_seed_corpus.zip $WORK/TestFuzzCodecs_corpus/*
fi

# Pack seed corpora for TestFuzzClientRdpFile
if [ -f $OUT/TestFuzzClientRdpFile ]; then
    zip --junk-paths --quiet $OUT/TestFuzzClientRdpFile_seed_corpus.zip \
        client/common/test/rdp-testcases/*.rdp
fi
# Disable leak detection for the RAIL fuzzer (rail_order_recv stream-ownership leak).
if [ -f $OUT/TestFuzzChannelRail ]; then
    printf '[asan]\ndetect_leaks=0\n' > $OUT/TestFuzzChannelRail.options
fi

# Build test
mkdir $SRC/FreeRDP/build-test
cd $SRC/FreeRDP/build-test
# LOCAL-ONLY: WITH_JSON_DISABLED, see note above (focal json libs too old).
cmake -DBUILD_TESTING=True -DWITH_JSON_DISABLED=ON ..
make
