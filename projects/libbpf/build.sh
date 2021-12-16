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

# This script is supposed to be compatible with OSS-Fuzz, i.e. it has to use
# environment variables like $CC, $CFLAGS, $OUT, link the fuzz targets with CXX
# (even though the project is written in C) and so on:
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#buildsh

# It can be used to build and run the fuzz targets using Docker and the images
# provided by the OSS-Fuzz project: https://google.github.io/oss-fuzz/advanced-topics/reproducing/#building-using-docker

# It can also be used to build and run the fuzz target locally without Docker.
# After installing clang and the build dependencies of libelf by running something
# like `dnf build-dep elfutils-devel` on Fedora or `apt-get build-dep libelf-dev`
# on Debian/Ubuntu, the following commands should be run:
#
#  $ git clone https://github.com/google/oss-fuzz
#  $ cd oss-fuzz/projects/libbpf
#  $ git clone https://github.com/libbpf/libbpf
#  $ ./build.sh
#  $ unzip -d CORPUS ./out/bpf-object-fuzzer_seed_corpus.zip
#  $ ./out/bpf-object-fuzzer CORPUS


set -eux

SANITIZER=${SANITIZER:-address}
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER -fsanitize=fuzzer-no-link"

export CC=${CC:-clang}
export CFLAGS=${CFLAGS:-$flags}

export CXX=${CXX:-clang++}
export CXXFLAGS=${CXXFLAGS:-$flags}

export SRC=${SRC:-$(realpath -- $(dirname -- "$0"))}
cd "$SRC/libbpf"

export OUT=${OUT:-"$SRC/out"}
mkdir -p "$OUT"

export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}

# Ideally libbelf should be built using release tarballs available
# at https://sourceware.org/elfutils/ftp/. Unfortunately sometimes they
# fail to compile (for example, elfutils-0.185 fails to compile with LDFLAGS enabled
# due to https://bugs.gentoo.org/794601) so let's just point the script to
# commits referring to versions of libelf that actually can be built
rm -rf elfutils
git clone git://sourceware.org/git/elfutils.git
(
cd elfutils
git checkout 983e86fd89e8bf02f2d27ba5dce5bf078af4ceda
git log --oneline -1

# ASan isn't compatible with -Wl,--no-undefined: https://github.com/google/sanitizers/issues/380
find -name Makefile.am | xargs sed -i 's/,--no-undefined//'

# ASan isn't compatible with -Wl,-z,defs either:
# https://clang.llvm.org/docs/AddressSanitizer.html#usage
sed -i 's/^\(ZDEFS_LDFLAGS=\).*/\1/' configure.ac


autoreconf -i -f
if ! ./configure --enable-maintainer-mode --disable-debuginfod --disable-libdebuginfod \
	    CC="$CC" CFLAGS="-Wno-error $CFLAGS" CXX="$CXX" CXXFLAGS="-Wno-error $CXXFLAGS" LDFLAGS="$CFLAGS"; then
    cat config.log
    exit 1
fi

make -C config -j$(nproc) V=1
make -C lib -j$(nproc) V=1
make -C libelf -j$(nproc) V=1
)

make -C src BUILD_STATIC_ONLY=y V=1 clean
make -C src -j$(nproc) CFLAGS="-I$(pwd)/elfutils/libelf $CFLAGS" BUILD_STATIC_ONLY=y V=1

$CC $CFLAGS -Isrc -Iinclude -Iinclude/uapi -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64  -c "$SRC/bpf-object-fuzzer.c" -o bpf-object-fuzzer.o
ZLIB_DIR=$(pkg-config --variable=libdir zlib)
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE bpf-object-fuzzer.o src/libbpf.a "$(pwd)/elfutils/libelf/libelf.a" "$ZLIB_DIR/libz.a" -o "$OUT/bpf-object-fuzzer"

# minimal.bpf.o was borrowed from https://github.com/libbpf/libbpf-bootstrap
# and was generated with
#   $ clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I.output -I../../libbpf/include/uapi \
#          -I../../vmlinux/ -idirafter /usr/local/include -idirafter /usr/lib64/clang/11.0.0/include \
#          -idirafter /usr/include -c minimal.bpf.c -o .output/minimal.bpf.o
#   $ llvm-strip -g .output/minimal.bpf.o
# In theory it's possible to generate it on the fly so as not to keep it in the repository
# but clang on OSS-Fuzz doesn't support -target bpf
zip -j "$OUT/bpf-object-fuzzer_seed_corpus.zip" "$SRC/minimal.bpf.o"
