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

# Specific C files to compile (excluding requester/mctp.c which depends on libmctp)
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
    "powersmoothing-powerprofile-api-v2.c"
    "fpga/fpga-controller.c"
    "fpga/fpga-maps.c"
    "fpga/fpga-rules-lp30-dimm.c"
    "fpga/fpga-rules-lp30-links.c"
    "fpga/fpga-rules-lp30-optics.c"
    "fpga/fpga-rules-lp30-pdb.c"
    "fpga/fpga-rules-lp30-sdm.c"
    "fpga/fpga-rules-lp30.c"
    "fpga/fpga-run.c"
    "fpga/fpga-tables.c"
)

rm -f *.o

# Compile C library files
for f in "${LIBNSM_SRCS[@]}"; do
    $CC $CFLAGS -c "$SRC/nsmd/libnsm/$f" \
        -DENABLE_SYSTEM_GUID \
        -DENABLE_GRACE_SPI_OPERATIONS \
        -I$SRC/nsmd \
        -I$SRC/nsmd/libnsm \
        -I$SRC/nsmd/libnsm/fpga \
        -I$SRC/nsmd/common \
        -o "$(basename "$f" .c).o"
done

# Compile and link each C++ fuzzer harness into a separate executable
for f in $SRC/decode_*_fuzzer.cc $SRC/nsm_*_fuzzer.cc; do
    name=$(basename "$f" .cc)
    $CXX $CXXFLAGS -std=c++23 \
        -DENABLE_SYSTEM_GUID \
        -DENABLE_GRACE_SPI_OPERATIONS \
        -I$SRC/nsmd \
        -I$SRC/nsmd/libnsm \
        -I$SRC/nsmd/libnsm/fpga \
        -I$SRC/nsmd/common \
        *.o \
        "$f" \
        -o "$OUT/$name" \
        $LIB_FUZZING_ENGINE \
        -lm
    cp $SRC/nsm.dict "$OUT/$name.dict"
done

cp $SRC/*.options "$OUT/"
python3 $SRC/generate_seeds.py "$OUT"
