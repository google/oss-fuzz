#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

export CFLAGS="$CFLAGS -Wno-error=nan-infinity-disabled"
export CXXFLAGS="$CXXFLAGS -Wno-error=nan-infinity-disabled"
$SRC/librawspeed/.ci/oss-fuzz.sh

# Prepare corpus seeds for Interpolator fuzzer
python3 "$SRC/librawspeed/fuzz/librawspeed/fuzz/generate_seeds_cr2sraw.py" --out "$SRC/cr2sraw-seeds"
zip -q -j "$OUT/Cr2sRawInterpolatorFuzzer_seed_corpus.zip" "$SRC"/cr2sraw-seeds/*

