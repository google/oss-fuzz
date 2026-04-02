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

# Build libopenapv
build_dir=$WORK/build
mkdir -p ${build_dir}
pushd ${build_dir}
rm -rf ./*

cmake $SRC/openapv \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_BUILD_TYPE=Release

make -j$(nproc) oapv_static
popd

# Build the decoder fuzzer
$CC $CFLAGS -I$SRC/openapv/inc \
    -I$SRC/openapv/app \
    -I$SRC/openapv \
    -I${build_dir}/include \
    -c $SRC/oapv_dec_fuzzer.c -o $WORK/oapv_dec_fuzzer.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $WORK/oapv_dec_fuzzer.o \
    -L${build_dir}/lib -loapv \
    -lpthread \
    -o $OUT/oapv_dec_fuzzer

# Generate seed corpus from the encoder
if [ -x "${build_dir}/bin/oapv_app_enc" ]; then
    mkdir -p $WORK/seed_corpus
    # Create a tiny 10-bit YUV test input
    python3 -c "
import struct
w, h = 64, 64
y = b''.join(struct.pack('<H', (128+(x%64))<<2) for x in range(w*h))
u = b''.join(struct.pack('<H', 512) for _ in range(w//2*h//2))
v = b''.join(struct.pack('<H', 800) for _ in range(w//2*h//2))
open('$WORK/test.yuv', 'wb').write(y+u+v)
"
    for qp in 10 30 50; do
        LD_LIBRARY_PATH=${build_dir}/lib ${build_dir}/bin/oapv_app_enc \
            -i $WORK/test.yuv -o $WORK/seed_corpus/seed_q${qp}.apv \
            -w 64 -h 64 -z 30 -q $qp -d 10 --input-csp 1 2>/dev/null || true
    done
    cd $WORK/seed_corpus && zip -j $OUT/oapv_dec_fuzzer_seed_corpus.zip *.apv 2>/dev/null || true
fi
