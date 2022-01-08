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

# Build libvpx
build_dir=$WORK/build
rm -rf ${build_dir}
mkdir -p ${build_dir}
pushd ${build_dir}

# oss-fuzz has 2 GB total memory allocation limit. So, we limit per-allocation
# limit in libvpx to 1 GB to avoid OOM errors. A smaller per-allocation is
# needed for MemorySanitizer (see bug oss-fuzz:9497 and bug oss-fuzz:9499).
if [[ $CFLAGS = *sanitize=memory* ]]; then
  extra_c_flags='-DVPX_MAX_ALLOCABLE_MEMORY=536870912'
else
  extra_c_flags='-DVPX_MAX_ALLOCABLE_MEMORY=1073741824'
fi

LDFLAGS="$CXXFLAGS" LD=$CXX $SRC/libvpx/configure \
    --enable-vp9-highbitdepth \
    --disable-unit-tests \
    --disable-examples \
    --size-limit=12288x12288 \
    --extra-cflags="${extra_c_flags}" \
    --disable-webm-io \
    --enable-debug \
    --disable-vp8-encoder \
    --disable-vp9-encoder
make -j$(nproc) all
popd

# build fuzzers
fuzzer_src_name=vpx_dec_fuzzer
fuzzer_decoders=( 'vp9' 'vp8' )
for decoder in "${fuzzer_decoders[@]}"; do
  fuzzer_name=${fuzzer_src_name}"_"${decoder}

  $CXX $CXXFLAGS -std=c++11 \
    -DDECODER=${decoder} \
    -I$SRC/libvpx \
    -I${build_dir} \
    -Wl,--start-group \
    $LIB_FUZZING_ENGINE \
    $SRC/libvpx/examples/${fuzzer_src_name}.cc -o $OUT/${fuzzer_name} \
    ${build_dir}/libvpx.a \
    -Wl,--end-group
  cp $SRC/vpx_fuzzer_seed_corpus.zip $OUT/${fuzzer_name}_seed_corpus.zip
  cp $SRC/vpx_dec_fuzzer.dict $OUT/${fuzzer_name}.dict
done
