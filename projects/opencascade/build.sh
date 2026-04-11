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

# Build OpenCASCADE as a set of static libraries, then link the IGES fuzzer
# harness against them. We disable as many modules as possible to keep the
# build fast, but TKDEIGES depends on TKService (which needs X11), so we
# cannot fully disable the Visualization module.

cd $SRC/occt

mkdir -p build_oss_fuzz
cd build_oss_fuzz

cmake -S .. -B . \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_MODULE_Visualization=OFF \
    -DBUILD_MODULE_Draw=OFF \
    -DBUILD_MODULE_ApplicationFramework=OFF \
    -DBUILD_LIBRARY_TYPE=Static \
    -DUSE_FREETYPE=OFF \
    -DUSE_TK=OFF \
    -DUSE_TCL=OFF \
    -DUSE_OPENGL=OFF \
    -DUSE_GLES2=OFF \
    -DUSE_VTK=OFF \
    -DUSE_RAPIDJSON=OFF \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS"

make -j$(nproc)

# ----------------------------------------------------------------------------
# Collect all static libraries produced by the build
# ----------------------------------------------------------------------------
LIBDIR="$SRC/occt/build_oss_fuzz/lin64/gcc/lib"
if [ ! -d "$LIBDIR" ]; then
    # Fallback: search for the directory containing .a files
    LIBDIR=$(dirname $(find $SRC/occt/build_oss_fuzz -name "libTKernel.a" -print -quit))
fi

# ----------------------------------------------------------------------------
# Build the fuzzer harness and link against all OCCT static libraries
# ----------------------------------------------------------------------------
$CXX $CXXFLAGS \
    -I$SRC/occt/src \
    -I$SRC/occt/build_oss_fuzz \
    $(find $SRC/occt/src -maxdepth 1 -type d -printf "-I%p\n") \
    -c $SRC/occt_fuzz_iges.cpp \
    -o $WORK/occt_fuzz_iges.o

$CXX $CXXFLAGS \
    $WORK/occt_fuzz_iges.o \
    -Wl,--start-group $(ls ${LIBDIR}/*.a) -Wl,--end-group \
    $LIB_FUZZING_ENGINE \
    -lpthread -lm -ldl -lX11 \
    -o $OUT/occt_fuzz_iges

# ----------------------------------------------------------------------------
# Dictionary
# ----------------------------------------------------------------------------
cp $SRC/occt_fuzz_iges.dict $OUT/occt_fuzz_iges.dict

# ----------------------------------------------------------------------------
# Seed corpus -- generated at build time so the OSS-Fuzz repo stays small
# and the seeds always match the harness's expected layout.
# ----------------------------------------------------------------------------
mkdir -p $WORK/occt_fuzz_iges_seeds
python3 $SRC/occt_fuzz_iges_seedgen.py $WORK/occt_fuzz_iges_seeds
(cd $WORK/occt_fuzz_iges_seeds && zip -q -r $OUT/occt_fuzz_iges_seed_corpus.zip .)
