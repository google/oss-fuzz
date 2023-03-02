#!/bin/bash -eu
# Copyright 2023 Google LLC
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

set -eox pipefail

FUZZ_CRATE_DIRS=$(find . -type d -name fuzz -exec dirname $(readlink -f {}) \;)

for CRATE_DIR in ${FUZZ_CRATE_DIRS[@]};
do
  echo "Building crate: $CRATE_DIR"
  cd $CRATE_DIR
  cargo +nightly fuzz build -O --debug-assertions
  FUZZ_TARGET_OUTPUT_DIR=fuzz/target/x86_64-unknown-linux-gnu/release
  for f in fuzz/fuzz_targets/*.rs
  do
      FUZZ_TARGET_NAME=$(basename ${f%.*})
      CRATE_NAME=$(basename $CRATE_DIR)
      cp $FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME $OUT/$CRATE_NAME-$FUZZ_TARGET_NAME
  done
done
