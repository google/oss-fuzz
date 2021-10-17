#!/bin/bash -e
# Copyright 2021 Google Inc.
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

SANITIZER=${SANITIZER:-address}
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER -fsanitize=fuzzer-no-link"

export CC=${CC:-clang}
export CFLAGS=${CFLAGS:-$flags}

export CXX=${CXX:-clang++}
export CXXFLAGS=${CXXFLAGS:-$flags}

export OUT=${OUT:-$(pwd)/out}
mkdir -p "$OUT"

export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}

rm -rf elfutils
git clone --depth=1 git://sourceware.org/git/elfutils.git
(
cd elfutils &&
find -name Makefile.am | xargs sed -i 's/,--no-undefined//' &&
sed -i 's/^\(ZDEFS_LDFLAGS=\).*/\1/' configure.ac &&
autoreconf -i -f &&
./configure --enable-maintainer-mode --disable-debuginfod CC="$CC" CFLAGS="-Wno-error $CFLAGS" CXX="$CXX" CXXFLAGS="-Wno-error $CXXFLAGS" LDFLAGS="$CFLAGS" &&
make -C config -j$(nproc) V=1 &&
make -C lib -j$(nproc) V=1 &&
make -C libelf -j$(nproc) V=1
)

make -C src BUILD_STATIC_ONLY=y V=1 clean
make -C src -j$(nproc) CFLAGS="-I$(pwd)/elfutils/libelf $CFLAGS" BUILD_STATIC_ONLY=y V=1

$CC $CFLAGS -Isrc -Iinclude -Iinclude/uapi -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64  -c "$SRC/bpf-object-fuzzer.c" -o bpf-object-fuzzer.o
ZLIB_DIR=$(pkg-config --variable=libdir zlib)
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE bpf-object-fuzzer.o src/libbpf.a "$(pwd)/elfutils/libelf/libelf.a" "$ZLIB_DIR/libz.a" -o "$OUT/bpf-object-fuzzer"

zip -j "$OUT/bpf-object-fuzzer_seed_corpus.zip" "$SRC/minimal.bpf.o"
