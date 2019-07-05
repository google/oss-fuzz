#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Build project and fuzzers
./bootstrap
./configure --without-bluez --enable-fuzzing
make -j$(nproc) all

# Remove artifacts
rm -f $OUT/*.zip

# Zip corpora and copy fuzzers
for dir in $(find src/test-apps/fuzz/corpus/ -maxdepth 1 -mindepth 1);
do
  # Remove "Fuzz" prefix in corpus directory name if necessary
  orig_name=$(basename $dir | sed 's/^Fuzz//g')
  fuzzer_name=Fuzz"${orig_name}"
  cp -f $dir/../../${fuzzer_name} $OUT
  zip -rq $OUT/"${fuzzer_name}"_seed_corpus $dir
done
