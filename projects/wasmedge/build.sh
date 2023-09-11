#!/bin/bash -eu
# Copyright 2023 Google LLC
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

export CFLAGS="$CFLAGS -fuse-ld=lld"
export CXXFLAGS="$CXXFLAGS -fuse-ld=lld"

cd "$SRC/WasmEdge"
sed -ie 's@core lto native@core native@' cmake/Helper.cmake
cmake -GNinja -Bbuild -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DWASMEDGE_FORCE_DISABLE_LTO=ON \
  -DWASMEDGE_BUILD_FUZZING=ON \
  -DWASMEDGE_BUILD_TOOLS=OFF \
  -DWASMEDGE_BUILD_TESTS=OFF \
  -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
  -DCMAKE_C_COMPILER_AR="$(command -v llvm-ar)" \
  -DCMAKE_C_COMPILER_RANLIB="$(command -v llvm-ranlib)" \
  -DCMAKE_CXX_COMPILER_AR="$(command -v llvm-ar)" \
  -DCMAKE_CXX_COMPILER_RANLIB="$(command -v llvm-ranlib)" \
  -DLLVM_DIR="/usr/lib/llvm-12/lib/cmake/llvm" \
  -DLLD_DIR="/usr/lib/llvm-12/lib/cmake/lld" \
  .
ninja -C build
cp -a build/lib/api/libwasmedge*.so* build/tools/fuzz/wasmedge-fuzz* "$OUT"/
cd utils/corpus/po
zip -9 "$OUT/wasmedge-fuzzpo_seed_corpus.zip" -R '*.txt'
cd -

cd "$SRC/WasmEdge-unittest"
zip -9 "$OUT/wasmedge-fuzztool_seed_corpus.zip" -R '*.wasm'
cd -

for i in build/tools/fuzz/wasmedge-fuzz*; do
  j="$(basename "$i")"
  patchelf --set-rpath \$ORIGIN "$OUT/${j}"
done

for i in libLLVM-12.so.1 libedit.so.2 libbsd.so.0; do
  cp "/usr/lib/x86_64-linux-gnu/${i}" "$OUT/"
  patchelf --set-rpath \$ORIGIN "$OUT/${i}"
done
