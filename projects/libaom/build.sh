#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# Build libaom
pushd $WORK
rm -rf ./*
cmake $SRC/aom -DCONFIG_PIC=1 -DCONFIG_SCALABILITY=0 -DCONFIG_LOWBITDEPTH=1 \
  -DENABLE_EXAMPLES=0 -DENABLE_DOCS=0 -DCONFIG_UNIT_TESTS=0 \
  -DCONFIG_SIZE_LIMIT=1 -DDECODE_HEIGHT_LIMIT=12288 -DDECODE_WIDTH_LIMIT=12288
make -j$(nproc)
popd

# Build some libaom utils that are not part of the core lib.
$CC $CFLAGS -std=c99 -c \
  -I$SRC/aom \
  -I$WORK \
  $SRC/aom/common/ivfdec.c -o $WORK/ivfdec.o

$CC $CFLAGS -std=c99 -c \
  -I$SRC/aom \
  -I$WORK \
  $SRC/aom/common/tools_common.c -o $WORK/tools_common.o

# build fuzzers
fuzzer_modes=( serial threaded )

for mode in "${fuzzer_modes[@]}"; do
  fuzzer_src_name=av1_dec_fuzzer
  fuzzer_name=${fuzzer_src_name}_${mode}

  $CXX $CXXFLAGS -std=c++11 \
    -DDECODE_MODE_${mode} \
    -I$SRC/aom \
    -I$WORK \
    -Wl,--start-group \
    -lFuzzingEngine \
    $SRC/${fuzzer_src_name}.cc -o $OUT/${fuzzer_name} \
    $WORK/libaom.a $WORK/ivfdec.o $WORK/tools_common.o \
    -Wl,--end-group

  # copy seed corpus.
  cp $SRC/dec_fuzzer_seed_corpus.zip $OUT/${fuzzer_name}_seed_corpus.zip
done
