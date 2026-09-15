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

# Specific C files to compile (excluding instance-id.c which depends on libmctp)
LIBNSM_SRCS=(
    "base.c"
    "debug-token.c"
    "device-capability-discovery.c"
    "device-configuration.c"
    "diagnostics.c"
    "firmware-utils.c"
    "network-ports.c"
    "pci-links.c"
    "platform-environmental.c"
)

# Compile C library files
for f in "${LIBNSM_SRCS[@]}"; do
    $CC $CFLAGS -c "$SRC/nsmd/libnsm/$f" -I$SRC/nsmd -I$SRC/nsmd/libnsm -o "$(basename "$f" .c).o"
done

# Compile and link each C++ fuzzer harness into a separate executable
for f in $SRC/decode_*_fuzzer.cc; do
    name=$(basename "$f" .cc)
    $CXX $CXXFLAGS -std=c++23 \
        -I$SRC/nsmd \
        -I$SRC/nsmd/libnsm \
        *.o \
        "$f" \
        -o "$OUT/$name" \
        $LIB_FUZZING_ENGINE
done
