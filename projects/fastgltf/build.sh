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

rm -rf $WORK/build
cmake -S . -B $WORK/build -G Ninja -DFASTGLTF_ENABLE_FUZZING=ON
cmake --build $WORK/build --parallel
cp $WORK/build/tests/fuzz/*_fuzzer $OUT/

# Paths are kept since many sample assets share file names.
find $SRC/glTF-Sample-Assets $SRC/fastgltf/tests/gltf -type f \
    \( -name '*.gltf' -o -name '*.glb' \) -size -1024k |
    zip -q $OUT/gltf_fuzzer_seed_corpus.zip -@
