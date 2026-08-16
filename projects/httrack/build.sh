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
# afl-cc rewrites -fcf-protection into CFI+LTO, emitting bitcode objects GNU
# binutils can't archive/link: drop the CET flag, archive with the llvm tools.
ax_cv_check_cflags___fcf_protection=no \
    ./configure --disable-shared --disable-https AR=llvm-ar RANLIB=llvm-ranlib
make -j"$(nproc)" -C src libhttrack.la

for f in charset meta idna entities unescape filters url; do
    $CC $CFLAGS -DHAVE_CONFIG_H -I. -Isrc -Isrc/coucal \
        -c "fuzz/fuzz-$f.c" -o "fuzz-$f.o"
    # shellcheck disable=SC2086
    $CXX $CXXFLAGS "fuzz-$f.o" -o "$OUT/fuzz-$f" \
        $LIB_FUZZING_ENGINE src/.libs/libhttrack.a -lz -lpthread
    zip -j "$OUT/fuzz-${f}_seed_corpus.zip" fuzz/corpus/"$f"/*
done
