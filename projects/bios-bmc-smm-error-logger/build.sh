#!/bin/bash -eu
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

cd $SRC/bios-bmc-smm-error-logger

# Disable C99 extension warning in C++ (triggered by SD_BUS_ERROR_NULL in systemd headers)
export CXXFLAGS="$CXXFLAGS -Wno-c99-extensions"
export LDFLAGS="${LDFLAGS:-$CXXFLAGS}"

# Reset git trees for idempotent local rebuilds
git checkout -- .
rm -rf fuzzing builddir
git -C subprojects/sdbusplus checkout -- .
git -C subprojects/stdplus checkout -- .

# Apply fuzzing integration and libc++ compatibility patches
git apply $SRC/fuzz.patch
git -C subprojects/sdbusplus apply $SRC/sdbusplus.patch
git -C subprojects/stdplus apply $SRC/stdplus.patch

# Copy fuzz target and Meson build definition into the source tree
mkdir -p fuzzing
cp $SRC/rde_fuzz.cpp fuzzing/
cp $SRC/fuzzing_meson.build fuzzing/meson.build

meson setup builddir \
    --wrap-mode=nodownload \
    --buildtype=plain \
    -Dfuzzing=enabled \
    -Dfuzzing_engine="$LIB_FUZZING_ENGINE" \
    -Dtests=disabled \
    -Dwerror=false \
    -Ddefault_library=static \
    -Dstdplus:gtest=disabled \
    -Dstdplus:tests=disabled \
    -Dstdplus:examples=false \
    -Dphosphor-dbus-interfaces:generate_md=false \
    -Dphosphor-dbus-interfaces:data_com_ampere=false \
    -Dphosphor-dbus-interfaces:data_com_google=false \
    -Dphosphor-dbus-interfaces:data_com_ibm=false \
    -Dphosphor-dbus-interfaces:data_com_intel=false \
    -Dphosphor-dbus-interfaces:data_com_meta=false \
    -Dphosphor-dbus-interfaces:data_com_qualcomm=false \
    -Dphosphor-dbus-interfaces:data_org_freedesktop=false \
    -Dphosphor-dbus-interfaces:data_org_open_power=false

ninja -C builddir fuzzing/rde_fuzz

cp builddir/fuzzing/rde_fuzz $OUT/
cp $SRC/rde_fuzz.dict $OUT/
cp $SRC/rde_fuzz.options $OUT/
python3 $SRC/generate_seeds.py subprojects/libbej/test $OUT/rde_fuzz_seed_corpus.zip
