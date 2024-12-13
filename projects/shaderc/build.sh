#!/bin/bash -eu
#
# Copyright 2024 Google LLC
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

# Sync dependencies
./utils/git-sync-deps

# Build the project binaries with ninja and cmake
mkdir -p build
pushd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="$CXXFLAGS -pthread -stdlib=libc++" \
      -DSHADERC_SKIP_TESTS=True \
      -DSHADERC_ENABLE_TESTS=OFF \
      -DSHADERC_SKIP_EXAMPLES=True \
      -DSHADERC_ENABLE_EXAMPLES=OFF \
      ..
ninja -v
popd

for fuzzer in $(find $SRC -maxdepth 1 -name '*_fuzzer.cc'); do
  fuzz_basename=$(basename -s .cc $fuzzer)
  $CXX $CXXFLAGS -I$SRC/shaderc/libshaderc/include \
      -I$SRC/shaderc/libshaderc_util/include \
      -I$SRC/shaderc/glslc/src -I$SRC/shaderc/third_party/glslang \
      -c ${fuzzer} -o ${fuzz_basename}.o

  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
      ${fuzz_basename}.o -o $OUT/${fuzz_basename} \
      -Wl,--start-group \
      $SRC/shaderc/build/libshaderc/*.a \
      $SRC/shaderc/build/libshaderc_util/libshaderc_util.a \
      $SRC/shaderc/build/glslc/libglslc.a \
      -Wl,--end-group
  zip -q $OUT/${fuzz_basename}_seed_corpus.zip $SRC/glsl_seed/*
done

