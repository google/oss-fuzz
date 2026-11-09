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

# Disable C99 extension warning in C++ (triggered by SD_BUS_ERROR_NULL in systemd headers)
export CXXFLAGS="$CXXFLAGS -Wno-c99-extensions"

# Download subprojects (only top-level ones)
meson subprojects download

# Reset subprojects if they exist (for local rebuilding)
if [ -d subprojects/sdbusplus ]; then git -C subprojects/sdbusplus checkout -- .; fi
if [ -d subprojects/stdplus ]; then git -C subprojects/stdplus checkout -- .; fi

# Apply patch to meson.build and meson.options to enable fuzzing
git apply $SRC/meson.patch

# Copy fuzzer files into the source tree
mkdir -p fuzzing
cp $SRC/parse_cert_fuzzer.cpp fuzzing/
cp $SRC/fuzzing_meson.build fuzzing/meson.build

# Clean build directory
rm -rf builddir

# Configure the project with Meson (this will download nested subprojects like stdplus)
meson setup builddir \
    -Dfuzzing=enabled \
    -Dfuzzing_engine="$LIB_FUZZING_ENGINE" \
    -Dtests=disabled \
    -Dallow-expired=enabled \
    -Dwerror=false \
    -Ddefault_library=static \
    --buildtype=debugoptimized

# NOW patch the subprojects
# Patch sdbusplus missing include
sed -i '1s/^/#include <unistd.h>\n/' subprojects/sdbusplus/include/sdbusplus/event.hpp

# Apply systemd compatibility patch to sdbusplus
git -C subprojects/sdbusplus apply $SRC/sdbusplus.patch

# Apply libc++ compatibility patch to stdplus
git -C subprojects/stdplus apply $SRC/stdplus.patch

# Build the fuzzer
ninja -C builddir fuzzing/parse_cert_fuzzer

# Copy the fuzzer to $OUT
cp builddir/fuzzing/parse_cert_fuzzer $OUT/

# Package seed corpus
zip -j $OUT/parse_cert_fuzzer_seed_corpus.zip $SRC/corpus/*
