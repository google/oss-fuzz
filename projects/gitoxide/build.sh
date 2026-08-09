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

export CARGO_BUILD_TARGET_DIR=$WORK/shared_cache

FUZZ_CRATE_DIRS=$(find . -type d -name fuzz -exec dirname $(readlink -f {}) \;)

for CRATE_DIR in ${FUZZ_CRATE_DIRS[@]};
do
  echo "Building crate: $CRATE_DIR"
  cd $CRATE_DIR
  cargo +nightly fuzz build -O --debug-assertions
  FUZZ_TARGET_OUTPUT_DIR=$CARGO_BUILD_TARGET_DIR/x86_64-unknown-linux-gnu/release
  for f in fuzz/fuzz_targets/*.rs
  do
      FUZZ_TARGET_NAME=$(basename ${f%.*})
      CRATE_NAME=$(basename $CRATE_DIR)
      OUT_FUZZER_NAME=$OUT/$CRATE_NAME-$FUZZ_TARGET_NAME
      cp $FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME $OUT_FUZZER_NAME
      FUZZ_CORPUS_BUILDER=./fuzz/fuzz_targets/${FUZZ_TARGET_NAME}_corpus_builder.sh
      if test -f "$FUZZ_CORPUS_BUILDER"; then
          $FUZZ_CORPUS_BUILDER $SRC/gitoxide ${OUT_FUZZER_NAME}_seed_corpus.zip
      fi
      FUZZ_DICT=./fuzz/fuzz_targets/${FUZZ_TARGET_NAME}.dict
      if test -f "$FUZZ_DICT"; then
            cp $FUZZ_DICT ${OUT_FUZZER_NAME}.dict
      fi
  done
done
