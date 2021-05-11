#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# generic swift symbolizer
(
cd $SRC/llvm-project
git apply ../llvmsymbol.diff
cmake -G "Ninja" \
    -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
    -DLIBCXXABI_ENABLE_SHARED=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_TARGETS_TO_BUILD=X86 \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DLLVM_BUILD_TESTS=OFF \
    -DLLVM_INCLUDE_TESTS=OFF llvm
ninja -j$(nproc) llvm-symbolizer
cp bin/llvm-symbolizer $OUT/
)

git apply $SRC/patch.diff
# build project
mkdir grpc-swift-fuzz
cd grpc-swift-fuzz
swift package init --type=executable
cp $SRC/fuzz_pipeline_configurator.swift Sources/grpc-swift-fuzz/main.swift
cp -r ../Sources/Examples/Echo Sources/
cp $SRC/Package.swift Package.swift
# Maybe we should have a helper script to set $SWIFT_FLAGS
# for instance about -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION in -Xcc
swift build -c debug -Xswiftc -sanitize=fuzzer,address \
    -Xswiftc -parse-as-library -Xswiftc -static-stdlib \
    -Xswiftc -use-ld=/usr/bin/ld --static-swift-stdlib \
    --sanitize=address -Xcc="-fsanitize=fuzzer-no-link,address" \
    -Xcxx="-fsanitize=fuzzer-no-link,address"

(
cd .build/debug/
find . -maxdepth 1 -type f -name "*fuzz" -executable | while read i; do cp $i $OUT/"$i"-debug; done
)
swift build -c release -Xswiftc -sanitize=fuzzer,address \
    -Xswiftc -parse-as-library -Xswiftc -static-stdlib \
    -Xswiftc -use-ld=/usr/bin/ld --static-swift-stdlib \
    --sanitize=address -Xcc="-fsanitize=fuzzer-no-link,address" \
    -Xcxx="-fsanitize=fuzzer-no-link,address"
(
cd .build/release/
find . -maxdepth 1 -type f -name "*fuzz" -executable | while read i; do cp $i $OUT/"$i"-release; done
)
