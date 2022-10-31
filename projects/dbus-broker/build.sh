#!/bin/bash -eu
# Copyright 2022 Google LLC
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

# The MESON_* variables are passed to meson to build dbus-broker itself and the original
# variables are used to build the fuzz target without meson to make the script compatible
# with fuzz-introspector. Once the fuzz target is built with meson as well the MESON_*
# variables can be safely removed and CFLAGS/CXXFLAGS/LDFLAGS can be tweaked directly
# instead: https://github.com/google/oss-fuzz/pull/7583#issuecomment-1104011067
MESON_CFLAGS=${CFLAGS:-}
MESON_CXXFLAGS=${CXXFLAGS:-}
MESON_LDFLAGS=${LDFLAGS:-}

if [[ "$SANITIZER" == introspector ]]; then
    MESON_CFLAGS="${MESON_CFLAGS//-fuse-ld=gold/ }"
    MESON_CXXFLAGS="${MESON_CXXFLAGS//-fuse-ld=gold/ }"
    MESON_LDFLAGS="${MESON_LDFLAGS//-fuse-ld=gold/ }"
    MESON_LDFLAGS+=" -flto"
    export CC_LD=gold
    export CXX_LD=gold
fi

apt-get update -y

if [[ "$ARCHITECTURE" == i386 ]]; then
    apt-get install -y pkg-config:i386
else
    apt-get install -y pkg-config
fi

if [[ "$SANITIZER" == undefined ]]; then
    additional_ubsan_checks=alignment
    UBSAN_FLAGS="-fsanitize=$additional_ubsan_checks -fno-sanitize-recover=$additional_ubsan_checks"
    CFLAGS+=" $UBSAN_FLAGS"
    CXXFLAGS+=" $UBSAN_FLAGS"
    MESON_CFLAGS+=" $UBSAN_FLAGS"
    MESON_CXXFLAGS+=" $UBSAN_FLAGS"
fi

pip3 install meson ninja

if ! CFLAGS="$MESON_CFLAGS" CXXFLAGS="$MESON_CXXFLAGS" LDFLAGS="$MESON_LDFLAGS" meson -Db_lundef=false -Dlauncher=false build; then
    cat build/meson-logs/meson-log.txt
    exit 1
fi

ninja -C ./build -v
$CC $CFLAGS -c -o fuzz-message.o -Isrc -I subprojects/libcstdaux-*/src -std=c11 -D_GNU_SOURCE "$SRC/fuzz-message.c"
$CXX $CXXFLAGS -o "$OUT/fuzz-message" \
    fuzz-message.o \
    build/src/libbus-static.a \
    build/subprojects/libcdvar-*/src/libcdvar-*.a \
    build/subprojects/libcutf8-*/src/libcutf8-*.a \
    $LIB_FUZZING_ENGINE
