#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Upstream replaced the v2 header (tiny_gltf.h) with the v3 parser and moved
# the harnesses from tests/fuzzer (meson) to tests/v3/fuzzer (plain Makefile).
# The old harnesses now live in attic/ and no longer compile, since the header
# they include is gone. Build the v3 harnesses directly here instead of going
# through upstream's Makefile, which hardcodes clang and its own -fsanitize
# flags and so cannot be used under OSS-Fuzz.
cd $SRC/tinygltf

# C++ harness: includes the header-only implementation via
# TINYGLTF3_IMPLEMENTATION, so it needs no extra translation unit.
$CXX $CXXFLAGS -std=c++17 -I. \
    tests/v3/fuzzer/fuzz_gltf_v3.cc \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_gltf_v3

# Pure-C harness: links against the separate tiny_gltf_v3.c implementation.
$CC $CFLAGS -std=c11 -I. -c tests/v3/fuzzer/fuzz_gltf_v3_c.c -o fuzz_gltf_v3_c.o
$CC $CFLAGS -std=c11 -I. -c tiny_gltf_v3.c -o tiny_gltf_v3.o
$CXX $CXXFLAGS \
    fuzz_gltf_v3_c.o tiny_gltf_v3.o \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_gltf_v3_c

# Seed corpus: glTF/GLB models shipped in the repo plus a few minimal inputs.
mkdir -p /tmp/seeds
find models -type f \( -name '*.gltf' -o -name '*.glb' \) \
    -exec cp {} /tmp/seeds/ \; 2>/dev/null || true
printf '{"asset":{"version":"2.0"},"scene":0,"scenes":[{"nodes":[0]}],"nodes":[{"name":"n"}]}' \
    > /tmp/seeds/minimal.gltf
printf 'glTF\x02\x00\x00\x00\x1c\x00\x00\x00\x04\x00\x00\x00JSON{}  ' \
    > /tmp/seeds/minimal.glb
printf '{"asset":{"version":"2.0"}}' > /tmp/seeds/asset_only.gltf
zip -qj $OUT/fuzz_gltf_v3_seed_corpus.zip /tmp/seeds/*
cp $OUT/fuzz_gltf_v3_seed_corpus.zip $OUT/fuzz_gltf_v3_c_seed_corpus.zip

# Build unit tests (used by run_tests.sh). tests/Makefile sets its include
# path with `CFLAGS ?= -I../ ...`, which is a no-op here because OSS-Fuzz
# exports CFLAGS, so pass the flags it needs explicitly.
make -C tests CFLAGS="$CFLAGS -I../ -std=c11"
