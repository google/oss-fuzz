#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

build_args=(
  -G Ninja
  -DBUILD_TESTING=OFF
  -DJPEGXL_ENABLE_BENCHMARK=OFF
  -DJPEGXL_ENABLE_DEVTOOLS=ON
  -DJPEGXL_ENABLE_EXAMPLES=OFF
  -DJPEGXL_ENABLE_FUZZERS=ON
  -DJPEGXL_ENABLE_MANPAGES=OFF
  -DJPEGXL_ENABLE_SJPEG=OFF
  -DJPEGXL_ENABLE_VIEWERS=OFF
  -DCMAKE_BUILD_TYPE=Release
)

# Build and generate a fuzzer corpus in release mode without instrumentation.
# This is done in a subshell since we change the environment.
(
  unset CFLAGS
  unset CXXFLAGS
  export AFL_NOOPT=1

  mkdir -p ${WORK}/libjxl-corpus
  cd ${WORK}/libjxl-corpus
  cmake "${build_args[@]}" "${SRC}/libjxl"
  ninja clean
  ninja fuzzer_corpus

  # Generate a fuzzer corpus.
  mkdir -p djxl_fuzzer_corpus
  tools/fuzzer_corpus -r djxl_fuzzer_corpus
  zip -j "${OUT}/djxl_fuzzer_seed_corpus.zip" djxl_fuzzer_corpus/*
)

# Build the fuzzers in release mode but force the inclusion of JXL_DASSERT()
# checks.
export CXXFLAGS="${CXXFLAGS} -DJXL_IS_DEBUG_BUILD=1"

mkdir -p ${WORK}/libjxl-fuzzer
cd ${WORK}/libjxl-fuzzer
cmake \
  "${build_args[@]}" \
  -DJPEGXL_FUZZER_LINK_FLAGS="${LIB_FUZZING_ENGINE}" \
  "${SRC}/libjxl"

fuzzers=(
  color_encoding_fuzzer
  djxl_fuzzer
  fields_fuzzer
  icc_codec_fuzzer
  rans_fuzzer
)

ninja clean
ninja "${fuzzers[@]}"
for fuzzer in "${fuzzers[@]}"; do
  cp tools/${fuzzer} "${OUT}/"
done
