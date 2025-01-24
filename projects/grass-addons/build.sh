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

# Create build directory
mkdir build || true
cd build || true

SRC_DIR=/src/grass-addons
FUZZ_TARGET=$SRC_DIR/Fuzz/fuzz_target.c

GRASS_INCLUDE_DIR=grass_include
mkdir -p $GRASS_INCLUDE_DIR/grass || true
curl -f -s -o $GRASS_INCLUDE_DIR/grass/gis.h https://raw.githubusercontent.com/OSGeo/grass/main/include/grass/gis.h || true
curl -f -s -o $GRASS_INCLUDE_DIR/grass/config.h https://raw.githubusercontent.com/OSGeo/grass-addons/master/grass6/raster/r.terracost/config.h || true
curl -f -s -o $GRASS_INCLUDE_DIR/grass/types.h https://raw.githubusercontent.com/OSGeo/grass-addons/master/grass6/raster/r.terracost/types.h || true

# Include directories for the headers
INCLUDE_DIRS=(
    "$SRC_DIR/include"
    "$SRC_DIR/src/raster/r.gwr"
    "$SRC_DIR/src/raster/r.skyline"
    "$SRC_DIR/src/raster/r.pops.spread/pops-core/tests"
    "$GRASS_INCLUDE_DIR"
)

INCLUDE_FLAGS=$(printf " -I%s" "${INCLUDE_DIRS[@]}")

for src_file in $SRC_DIR/Fuzz/*.c; do
    obj_file=$(basename "$src_file" .c).o
    clang $CFLAGS $INCLUDE_FLAGS -c "$src_file" -o "$SRC_DIR/$obj_file" -Wno-error -I/usr/include/c++/10 || true
done

OBJECT_FILES=($SRC_DIR/*.o)

clang $CXXFLAGS $INCLUDE_FLAGS $FUZZ_TARGET -o $OUT/fuzz_target "${OBJECT_FILES[@]}" || true