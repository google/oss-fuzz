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

# Build libxml2 as static library
cd $SRC
if [ ! -d libxml2 ]; then
    git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
fi
cd libxml2
mkdir -p build && cd build
cmake .. \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DBUILD_SHARED_LIBS=OFF \
    -DLIBXML2_WITH_PYTHON=OFF \
    -DLIBXML2_WITH_LZMA=OFF \
    -DLIBXML2_WITH_ZLIB=OFF \
    -DLIBXML2_WITH_ICU=OFF
make -j$(nproc)
LIBXML2_DIR="$SRC/libxml2"
LIBXML2_LIB="$LIBXML2_DIR/build/libxml2.a"
LIBXML2_INCLUDE_SRC="$LIBXML2_DIR/include"
LIBXML2_INCLUDE_BUILD="$LIBXML2_DIR/build"

# Build libiqxmlrpc with fuzzing instrumentation as static library
cd $SRC/libiqxmlrpc
mkdir -p build
cd build
cmake .. \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS -std=c++11 -DBOOST_TIMER_ENABLE_DEPRECATED -I$LIBXML2_INCLUDE_SRC -I$LIBXML2_INCLUDE_BUILD" \
    -DBUILD_SHARED_LIBS=OFF \
    -Dbuild_tests=OFF \
    -DLIBXML2_INCLUDE_DIR="$LIBXML2_INCLUDE_SRC;$LIBXML2_INCLUDE_BUILD" \
    -DLIBXML2_LIBRARY="$LIBXML2_LIB"

make -j$(nproc)
cd ..

# Build fuzz targets with static linking
for fuzzer in fuzz/fuzz_*.cc; do
    name=$(basename "$fuzzer" .cc)
    $CXX $CXXFLAGS -std=c++11 -DBOOST_TIMER_ENABLE_DEPRECATED \
        -I. -I"$LIBXML2_INCLUDE_SRC" -I"$LIBXML2_INCLUDE_BUILD" \
        "$fuzzer" \
        -o "$OUT/$name" \
        build/libiqxmlrpc/libiqxmlrpc.a \
        "$LIBXML2_LIB" \
        $LIB_FUZZING_ENGINE \
        -Wl,-Bstatic -lboost_date_time -lboost_thread -lboost_system \
        -Wl,-Bdynamic -lpthread
done

# Copy seed corpora from the repository
# The repo maintains corpus directories in fuzz/corpus/
for corpus_dir in fuzz/corpus/*/; do
    if [ -d "$corpus_dir" ]; then
        corpus_name=$(basename "$corpus_dir")
        fuzzer_name="fuzz_${corpus_name}"
        if [ -f "$OUT/$fuzzer_name" ]; then
            zip -j -q "$OUT/${fuzzer_name}_seed_corpus.zip" "$corpus_dir"/* 2>/dev/null || true
        fi
    fi
done

# Copy dictionaries and associate with fuzzers
# xml.dict -> XML-based fuzzers (request, response, value, dispatcher, serialize, packet)
for fuzzer in fuzz_request fuzz_response fuzz_value fuzz_dispatcher fuzz_serialize fuzz_packet; do
    if [ -f "$OUT/$fuzzer" ]; then
        cp fuzz/xml.dict "$OUT/${fuzzer}.dict"
    fi
done

# http.dict -> HTTP fuzzers
if [ -f "$OUT/fuzz_http" ]; then
    cp fuzz/http.dict "$OUT/fuzz_http.dict"
fi
if [ -f "$OUT/fuzz_xheaders" ]; then
    cp fuzz/http.dict "$OUT/fuzz_xheaders.dict"
fi

# inet_addr.dict -> inet_addr fuzzer
if [ -f "$OUT/fuzz_inet_addr" ]; then
    cp fuzz/inet_addr.dict "$OUT/fuzz_inet_addr.dict"
fi

# dispatcher.dict -> dispatcher fuzzer (in addition to xml.dict, use more specific one)
if [ -f "$OUT/fuzz_dispatcher" ]; then
    cp fuzz/dispatcher.dict "$OUT/fuzz_dispatcher.dict"
fi
