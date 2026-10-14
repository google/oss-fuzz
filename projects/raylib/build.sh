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

cd $SRC/raylib

$CC $CFLAGS -I./src -I./src/external \
    -DSUPPORT_TRACELOG=0 -DPLATFORM_DESKTOP -DGRAPHICS_API_OPENGL_33 \
    -c ./src/rmodels.c -o rmodels.o

$CC $CFLAGS -I./src -I./src/external \
    -DSUPPORT_TRACELOG=0 -DPLATFORM_DESKTOP -DGRAPHICS_API_OPENGL_33 \
    -c $SRC/raylib_stubs.c -o raylib_stubs.o

$CC $CFLAGS -I./src \
    -DRAYMATH_IMPLEMENTATION \
    -c -x c /dev/null -include ./src/raymath.h -o raymath_impl.o 2>/dev/null || \
    echo 'extern int raymath_dummy;' | $CC $CFLAGS -c -x c - -o raymath_impl.o

$CC $CFLAGS -I./src -I./src/external \
    -DSUPPORT_TRACELOG=0 -DPLATFORM_DESKTOP -DGRAPHICS_API_OPENGL_33 \
    $SRC/raylib_fuzz_model.c rmodels.o raylib_stubs.o raymath_impl.o \
    $LIB_FUZZING_ENGINE -lm -lpthread \
    -o $OUT/raylib_fuzz_model

cp $SRC/raylib_model.dict $OUT/raylib_fuzz_model.dict

mkdir -p /tmp/raylib_seeds
printf '\x00# OBJ\nv 0.0 0.0 0.0\nv 1.0 0.0 0.0\nv 0.0 1.0 0.0\nf 1 2 3\n' > /tmp/raylib_seeds/seed_obj
printf '\x01INTERQUAKEMODEL\x00\x02\x00\x00\x00' > /tmp/raylib_seeds/seed_iqm
dd if=/dev/zero bs=1 count=100 >> /tmp/raylib_seeds/seed_iqm 2>/dev/null
printf '\x02{"asset":{"version":"2.0"}}' > /tmp/raylib_seeds/seed_gltf
printf '\x04VOX \x96\x00\x00\x00' > /tmp/raylib_seeds/seed_vox
dd if=/dev/zero bs=1 count=50 >> /tmp/raylib_seeds/seed_vox 2>/dev/null
printf '\x053DMO' > /tmp/raylib_seeds/seed_m3d
dd if=/dev/zero bs=1 count=50 >> /tmp/raylib_seeds/seed_m3d 2>/dev/null

cd /tmp/raylib_seeds && zip -q -j $OUT/raylib_fuzz_model_seed_corpus.zip *
