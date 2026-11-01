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

# build project
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF ..
make -j$(nproc)
cp bin/fuzz* $OUT/

# Seed corpus and dictionary for the GeoJSON reader fuzzer.
cp $SRC/geos/tests/fuzz/geojson.dict $OUT/fuzz_geojson.dict
zip -j $OUT/fuzz_geojson_seed_corpus.zip $SRC/geos/tests/fuzz/geojson_seed_corpus/*
