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

(
cd llvm-project
git apply ../llvmsymbol.diff
cmake -G "Ninja" -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON -DLIBCXXABI_ENABLE_SHARED=OFF -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DLLVM_BUILD_TESTS=OFF -DLLVM_INCLUDE_TESTS=OFF llvm
ninja -j$(nproc) llvm-symbolizer
cp bin/llvm-symbolizer $OUT/
)

# build project
mkdir swift-protobuf-fuzz
cd swift-protobuf-fuzz
swift package init --type=executable
cp $SRC/fuzz_binary.swift Sources/swift-protobuf-fuzz/main.swift
cp $SRC/Package.swift Package.swift
cp ../swift-protobuf/Tests/SwiftProtobufTests/unittest.pb.swift Sources/swift-protobuf-fuzz/
cp ../swift-protobuf/Tests/SwiftProtobufTests/unittest_import.pb.swift Sources/swift-protobuf-fuzz/
cp ../swift-protobuf/Tests/SwiftProtobufTests/unittest_import_public.pb.swift Sources/swift-protobuf-fuzz/
swift build -c debug -Xswiftc -sanitize=address,fuzzer -Xswiftc -parse-as-library -Xswiftc -static-stdlib -Xswiftc -use-ld=/usr/bin/ld --static-swift-stdlib --sanitize=address
cp .build/x86_64-unknown-linux-gnu/debug/swift-protobuf-fuzz $OUT/
