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


# build project
mkdir swift-protobuf-fuzz
cd swift-protobuf-fuzz
swift package init --type=executable
cp $SRC/fuzz.swift Sources/swift-protobuf-fuzz/main.swift
cp $SRC/Package.swift Package.swift
cp ../swift-protobuf/Tests/SwiftProtobufTests/unittest.pb.swift Sources/swift-protobuf-fuzz/
cp ../swift-protobuf/Tests/SwiftProtobufTests/unittest_import.pb.swift Sources/swift-protobuf-fuzz/
cp ../swift-protobuf/Tests/SwiftProtobufTests/unittest_import_public.pb.swift Sources/swift-protobuf-fuzz/
swift build -c debug -Xswiftc -sanitize=fuzzer,address -Xswiftc -parse-as-library -Xswiftc -static-stdlib 
cp .build/x86_64-unknown-linux-gnu/debug/swift-protobuf-fuzz $OUT/
