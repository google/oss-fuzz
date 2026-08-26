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

. precompile_swift

# Build the fuzz targets from the sibling fuzzing package, which depends on
# the containerization package via a local path reference.
cd $SRC/fuzzing
swift build -c release $SWIFTFLAGS

for fuzzer in OCIManifestFuzzer OCIIndexFuzzer OCIImageConfigFuzzer OCISpecFuzzer OCIReferenceFuzzer; do
  cp ".build/release/$fuzzer" "$OUT/$fuzzer"
  if [ -d "seeds/$fuzzer" ]; then
    zip -j -q "$OUT/${fuzzer}_seed_corpus.zip" "seeds/$fuzzer"/*
  fi
done
