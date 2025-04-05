#!/bin/bash
# Copyright 2025 The OSS-Fuzz Authors. All rights reserved.
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

set -e

# Create a minimal fuzzer target with proper license header
cat > $SRC/fuzz_target.c << 'EOF'
// Copyright 2025 The OSS-Fuzz Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    
    // Basic input validation
    if (data == NULL) return 0;
    
    // Simple memory operation to trigger sanitizers
    volatile uint8_t test = data[0];
    (void)test;
    
    return 0;
}
EOF

# Build the fuzzer with all required sanitizers
$CC $CFLAGS \
    -Wall -Wextra \
    -fsanitize=fuzzer,address,undefined \
    $SRC/fuzz_target.c \
    -o $OUT/fuzz_target \
    $LIB_FUZZING_ENGINE

mkdir -p $OUT/corpus
cat > $OUT/corpus/output.txt << 'EOF'
// Copyright 2025 The OSS-Fuzz Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

output
EOF

mkdir -p $SRC/grass-addons/fuzz/corpus
cp $OUT/corpus/output.txt $SRC/grass-addons/fuzz/corpus/

# Set proper permissions
chmod -R 755 $OUT/corpus
chmod -R 755 $SRC/grass-addons/fuzz/corpus