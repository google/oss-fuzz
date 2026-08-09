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

# setup
build=$WORK/build

# cleanup
rm -rf $build
mkdir -p $build

# Build the library.
meson --default-library=static --wrap-mode=nodownload -Ddocs=false \
      -Dfuzzer_ldflags="$(echo $LIB_FUZZING_ENGINE)" \
      $build \
  || (cat build/meson-logs/meson-log.txt && false)

# Build the fuzzers.
ninja -v -j$(nproc) -C $build bin/fribidi-fuzzer
mv $build/bin/fribidi-fuzzer $OUT/

# Archive and copy to $OUT seed corpus if the build succeeded.
zip $OUT/fribidi-fuzzer_seed_corpus.zip test/*.{input,reference} test/fuzzing/*
