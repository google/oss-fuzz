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

# Build the static engine library with the OSS-Fuzz toolchain, then link the
# in-tree libFuzzer harnesses (fuzz/) against $LIB_FUZZING_ENGINE.
./bootstrap
# llvm-ar/ranlib: GNU ranlib leaves afl-clang-fast archives index-less.
./configure --disable-shared --disable-https AR=llvm-ar RANLIB=llvm-ranlib
make -j"$(nproc)" -C src libhttrack.la

# TEMPORARY DEBUG (revert before merge): identify why GNU ld rejects the
# afl-clang-fast archive (ELF vs bitcode vs empty members).
echo "=== DEBUG: toolchain ==="
ld --version | head -1 || true
$CC --version || true
echo "=== DEBUG: object/archive headers ==="
wc -c src/libhttrack_la-htscore.o || true
od -An -tx1 -N16 src/libhttrack_la-htscore.o || true
readelf -h src/libhttrack_la-htscore.o 2>&1 | head -8 || true
od -An -tx1 -N16 src/.libs/libhttrack.a || true
nm src/libhttrack_la-htscore.o 2>&1 | head -3 || true
llvm-nm src/libhttrack_la-htscore.o 2>&1 | head -3 || true

for f in charset meta idna entities unescape filters url; do
    $CC $CFLAGS -DHAVE_CONFIG_H -I. -Isrc -Isrc/coucal \
        -c "fuzz/fuzz-$f.c" -o "fuzz-$f.o"
    # shellcheck disable=SC2086
    $CXX $CXXFLAGS "fuzz-$f.o" -o "$OUT/fuzz-$f" \
        $LIB_FUZZING_ENGINE src/.libs/libhttrack.a -lz -lpthread ||
        { # TEMPORARY DEBUG: which link strategy survives?
            echo "=== DEBUG: default link failed, retrying with lld ==="
            # shellcheck disable=SC2086
            $CXX $CXXFLAGS -fuse-ld=lld "fuzz-$f.o" -o "$OUT/fuzz-$f" \
                $LIB_FUZZING_ENGINE src/.libs/libhttrack.a -lz -lpthread ||
                { echo "=== DEBUG: lld failed too, linking bare objects ==="
                    # shellcheck disable=SC2086
                    $CXX $CXXFLAGS "fuzz-$f.o" -o "$OUT/fuzz-$f" \
                        $LIB_FUZZING_ENGINE src/libhttrack_la-*.o \
                        src/coucal/libhttrack_la-*.o \
                        src/minizip/libhttrack_la-*.o -lz -lpthread; }; }
    zip -j "$OUT/fuzz-${f}_seed_corpus.zip" fuzz/corpus/"$f"/*
done
