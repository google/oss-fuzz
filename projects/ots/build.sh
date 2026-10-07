#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# Configure the project.
meson -Dfuzzer_ldflags="$(echo $LIB_FUZZING_ENGINE)" \
      --wrap-mode=forcefallback \
      $build \
   || (cat build/meson-logs/meson-log.txt && false)

# Build the fuzzer.
ninja -v -j$(nproc) -C $build ots-fuzzer
mv $build/ots-fuzzer $OUT/

cp $SRC/ots-fuzzer.options $OUT/
zip -j -r $OUT/ots-fuzzer_seed_corpus.zip $SRC/ots/tests/fonts
