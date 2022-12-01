#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

sed -i 's/check_inconsistencies=yes/check_inconsistencies=no/' common/acx_pthread.m4

./autogen.sh --disable-stack-protector --disable-qt3 --disable-qt4 --disable-qt5 --disable-gtk --disable-gtk3 --disable-dbus --disable-gdbm --disable-libdaemon --disable-python --disable-manpages --disable-mono --disable-monodoc --disable-glib --disable-gobject --disable-libevent
make -j "$(nproc)" V=1

for f in "$SRC/"*_fuzzer.c; do
    fuzz_target=$(basename "$f" .c)
    $CC -c $CFLAGS -I. \
        "$SRC/$fuzz_target.c" \
        -o "$fuzz_target.o"

    $CXX $CXXFLAGS \
        "$fuzz_target.o" \
        -o "$OUT/$fuzz_target" \
        $LIB_FUZZING_ENGINE \
        "avahi-core/.libs/libavahi-core.a" "avahi-common/.libs/libavahi-common.a"
done
