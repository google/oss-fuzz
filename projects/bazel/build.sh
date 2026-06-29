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
# OSS-Fuzz build script for the ijar class-parser fuzz target.
#
# StripClass() lives in third_party/ijar/classfile.cc and only depends on
# third_party/ijar/common.h (header-only helpers) — no zlib, no platform code —
# so a direct compile is sufficient and avoids a full Bazel bootstrap inside the
# fuzzing image.

cd "$SRC/bazel"

$CXX $CXXFLAGS -std=c++17 -I. \
  "$SRC/ijar_strip_fuzzer.cc" \
  third_party/ijar/classfile.cc \
  $LIB_FUZZING_ENGINE \
  -o "$OUT/ijar_strip_fuzzer"

# Seed corpus: a crashing Record-attribute class + small valid seeds help the
# engine reach the vulnerable re-emit path quickly.
if [ -d "$SRC/ijar_strip_fuzzer_seed_corpus" ]; then
  zip -j "$OUT/ijar_strip_fuzzer_seed_corpus.zip" \
      "$SRC/ijar_strip_fuzzer_seed_corpus"/* || true
fi
