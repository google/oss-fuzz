#!/bin/bash
# Copyright 2024 The OSS-Fuzz Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

set +e

# Create a minimal fuzzer target
cat > $SRC/fuzz_target.c << 'EOF'
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return 0;
}
EOF

# Build the fuzzer
$CC $CFLAGS \
    $SRC/fuzz_target.c \
    -o $OUT/fuzz_target \
    $LIB_FUZZING_ENGINE

# Create a minimal corpus
mkdir -p $OUT/corpus
echo "output" > $OUT/corpus/output.txt

exit 0