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

FUZZ_TARGET_DIR="target/x86_64-unknown-linux-gnu/release"

cd $SRC/keramics

cargo fuzz build -O --features fuzzing

for f in fuzz/fuzz_targets/*.rs
do
    FUZZ_TARGET=$(basename ${f%.*})

    if [ -d "test_data/${FUZZ_TARGET}" ]
    then
        zip $OUT/${FUZZ_TARGET}_seed_corpus.zip test_data/${FUZZ_TARGET}/*
    fi
    if [ -f "${FUZZ_TARGET_DIR}/${FUZZ_TARGET}" ]
    then
        cp ${FUZZ_TARGET_DIR}/${FUZZ_TARGET} $OUT/
    fi
done
