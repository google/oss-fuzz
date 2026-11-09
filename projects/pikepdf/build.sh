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

# See asan_deque_annotations_stub.c for why this is needed (oss-fuzz#12839).
# Only ASan builds reference the missing symbols; build the stub unconditionally
# anyway, it is a no-op for the other sanitizers.
$CC $CFLAGS -fPIC -c "$SRC"/asan_deque_annotations_stub.c \
    -o "$SRC"/asan_deque_annotations_stub.o
ASAN_STUB="$SRC"/asan_deque_annotations_stub.o

export QPDF_SOURCE_TREE="$SRC"/qpdf
export QPDF_BUILD_LIBDIR=$QPDF_SOURCE_TREE/build/libqpdf

# Build qpdf dependency
cd $QPDF_SOURCE_TREE
cmake -S . -B build \
    -DOSS_FUZZ=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_STANDARD=17 \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_SHARED_LINKER_FLAGS="$ASAN_STUB"
cmake --build build --parallel --target libqpdf

# Build pikepdf.
#
# pikepdf requests cxx_std_20, which makes CMake >= 3.28 turn on C++20 module
# dependency scanning for the Ninja generator. That requires clang-scan-deps,
# which is not shipped in the OSS-Fuzz base images, so configuration resolves
# it to CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS-NOTFOUND and every compile of
# src/core/*.cpp fails with "not found". pikepdf does not use C++20 modules,
# so scanning is pure overhead; turn it off.
cd "$SRC"/pikepdf
env QPDF_SOURCE_TREE=$QPDF_SOURCE_TREE QPDF_BUILD_LIBDIR=$QPDF_BUILD_LIBDIR \
    CC="$CC" CFLAGS="$CFLAGS" CXX="$CXX" CXXFLAGS="$CXXFLAGS" LDSHARED="$CXX -shared" \
    SKBUILD_CMAKE_DEFINE="CMAKE_CXX_SCAN_FOR_MODULES=OFF;CMAKE_SHARED_LINKER_FLAGS=$ASAN_STUB" \
    pip3 install --verbose .

# libqpdf's SOVERSION tracks qpdf's major version, so do not hardcode it.
LIBQPDF=$(ls "$QPDF_BUILD_LIBDIR"/libqpdf.so.* | grep -E 'libqpdf\.so\.[0-9]+$' | head -1)

# Build fuzzers in $OUT
for fuzzer in $(find fuzzing -name '*_fuzzer.py');do
  compile_python_fuzzer "$fuzzer" \
      --add-binary="$LIBQPDF:." \
      --add-binary="/lib/x86_64-linux-gnu/libz.so.1:." \
      --add-binary="/lib/x86_64-linux-gnu/libjpeg.so.8:."
done
zip -q -j $OUT/pikepdf_fuzzer_seed_corpus.zip $SRC/pikepdf/fuzzing/corpus/*
