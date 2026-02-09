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

# Screen's source is in the src/ subdirectory in newer versions,
# or directly in the repo root in older versions.
if [ -d "$SRC/screen/src" ]; then
    SCREEN_SRC="$SRC/screen/src"
else
    SCREEN_SRC="$SRC/screen"
fi

# The fuzz targets are standalone - they implement ANSI/VT parsing
# logic themselves and don't depend on the screen binary or its build.
# We compile them directly against the fuzzing engine.

# === fuzz_screen_ansi: ANSI/VT100 escape sequence parser ===
$CC $CFLAGS -c $SRC/fuzz_screen_ansi.c -o $SRC/fuzz_screen_ansi.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_screen_ansi.o \
    -o $OUT/fuzz_screen_ansi
cp $SRC/fuzz_screen_ansi.dict $OUT/ || true

# === fuzz_screen_utf8: UTF-8 sequence decoder ===
$CC $CFLAGS -c $SRC/fuzz_screen_utf8.c -o $SRC/fuzz_screen_utf8.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_screen_utf8.o \
    -o $OUT/fuzz_screen_utf8
cp $SRC/fuzz_screen_utf8.dict $OUT/ || true

# === fuzz_screen_escape: Screen command/escape parsing ===
$CC $CFLAGS -c $SRC/fuzz_screen_escape.c -o $SRC/fuzz_screen_escape.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_screen_escape.o \
    -o $OUT/fuzz_screen_escape
cp $SRC/fuzz_screen_escape.dict $OUT/ || true
