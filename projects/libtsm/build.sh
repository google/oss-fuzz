#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# build the library.
#
# --buildtype=plain so that meson adds no optimisation or debug flags of its
# own and $CFLAGS is what actually reaches the compiler.
# -Dwerror=false because the project defaults to werror=true, and a sanitizer
# build raises warnings upstream's own CI does not see.
#
# LDFLAGS has to carry the sanitizer flags too: meson.build declares libtsm as
# a shared_library, and linking one without -fsanitize=address leaves every
# __asan_* and __sanitizer_cov_* reference undefined.
# -Db_lundef=false drops meson's default -Wl,--no-undefined for the same
# reason: a sanitized shared object legitimately has undefined runtime symbols.
export LDFLAGS="${LDFLAGS:-} $CFLAGS"

meson setup build \
    --buildtype=plain \
    -Db_lundef=false \
    -Dwerror=false \
    -Dtests=false \
    -Dgtktsm=false
ninja -C build

# libtsm's meson.build declares only a shared library, so there is no static
# archive to link the fuzzer against. Rather than duplicate upstream's source
# list here -- which would silently go stale the next time a file is added --
# archive the objects ninja actually emitted for it.
#
# One directory, not three: libtsm's wcwidth and shl dependencies are declared
# with declare_dependency(sources: ...), so their translation units are
# recompiled into libtsm.so's own object directory. Adding the separate
# libwcwidth.a/libshl.a as well would define every one of their symbols twice.
#
# `find` rather than a shell glob: meson names an object built from outside the
# target's own directory after its relative path, so shl-htable.c.o and
# wcwidth.c.o land there as `.._shared_shl-htable.c.o` and
# `.._.._external_wcwidth_wcwidth.c.o`. A `*.o` glob does not match a leading
# dot, and would silently produce an archive missing exactly those two.
find build/src/tsm -name '*.o' -print0 | xargs -0 ar rcs $WORK/libtsm.a

# build your fuzzer(s)
$CC $CFLAGS -c $SRC/libtsm_fuzzer.c -Isrc/tsm -o $WORK/libtsm_fuzzer.o
$CXX $CXXFLAGS \
    -o $OUT/libtsm_fuzzer \
    $WORK/libtsm_fuzzer.o \
    $WORK/libtsm.a \
    $LIB_FUZZING_ENGINE
