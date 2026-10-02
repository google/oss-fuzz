#!/bin/bash -eu
# Copyright 2025 Google Inc.
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

# Build Jerryscript
python tools/build.py \
        --debug \
        --linker-flag '${CFLAGS}' \
        --compile-flag '${CFLAGS}' \
        --lto 'OFF' \
        --stack-limit=64 \
        --logging=on \
        --clean

# Build fuzzer
$CC $CFLAGS \
  -Ijerry-core/include \
  jerry-main/main-libfuzzer.c \
  build/lib/libjerry-core.a \
  build/lib/libjerry-ext.a \
  build/lib/libjerry-port.a \
  $LIB_FUZZING_ENGINE \
  -o $OUT/jerry_fuzzer

# Define dictionary
cp $SRC/fuzz.dict $OUT/jerry_fuzzer.dict

# Create corpus
find tests/jerry -name "*.js" -type f -print | zip -r $OUT/jerry_fuzzer_seed_corpus.zip -@
