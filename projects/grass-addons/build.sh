#!/bin/bash -u
#
# Copyright 2025 Google LLC
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

set -eux

SRC_DIR=/src/grass-addons
BUILD_DIR=/out
INSTALL_PREFIX=/usr/local
FUZZ_TARGET=$SRC_DIR/Fuzz/fuzz_target.c
OUT=$BUILD_DIR

mkdir -p build
cd build

apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    libstdc++-10-dev \
    clang \
    make \
    || true

GRASS_INCLUDE_DIR=grass_include
mkdir -p $GRASS_INCLUDE_DIR/grass

curl -f -s -o $GRASS_INCLUDE_DIR/grass/gis.h https://raw.githubusercontent.com/OSGeo/grass/main/include/grass/gis.h || true
curl -f -s -o $GRASS_INCLUDE_DIR/grass/config.h https://raw.githubusercontent.com/OSGeo/grass-addons/grass8/Fuzz/fuzz_target.c || true
curl -f -s -o $GRASS_INCLUDE_DIR/grass/types.h https://raw.githubusercontent.com/OSGeo/grass-addons/grass8/Fuzz/fuzz_target.c || true

INCLUDE_DIRS=(
    "$SRC_DIR/include"
    "$SRC_DIR/src/raster/r.gwr"
    "$SRC_DIR/src/raster/r.skyline"
    "$SRC_DIR/src/raster/r.pops.spread/pops-core/tests"
    "$GRASS_INCLUDE_DIR"
    "/usr/include/c++/10"
    "/usr/include/x86_64-linux-gnu/c++/10"
)

INCLUDE_FLAGS=$(printf " -I%s" "${INCLUDE_DIRS[@]}")

OBJECT_FILES=()
for src_file in $SRC_DIR/Fuzz/*.c; do
    if [[ -f "$src_file" ]]; then
        obj_file=$(basename "$src_file" .c).o
        clang $CFLAGS $INCLUDE_FLAGS -c "$src_file" -o "build/$obj_file" -Wno-error
        OBJECT_FILES+=("build/$obj_file")
    fi
done

mkdir -p $OUT

if [[ ${#OBJECT_FILES[@]} -gt 0 ]]; then
    clang $CXXFLAGS $INCLUDE_FLAGS build/*.o -o $OUT/fuzz_target
    exit 0
else
    exit 1
fi

if [[ ! -f "$OUT/fuzz_target" ]]; then
    exit 1
fi
