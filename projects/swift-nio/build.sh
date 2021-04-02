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
mkdir swift-nio-fuzz
cd swift-nio-fuzz
swift package init --type=executable
rm -Rf Sources/swift-nio-fuzz
mkdir Sources/swift-nio-http1-fuzz
cp $SRC/fuzz_http1.swift Sources/swift-nio-http1-fuzz/main.swift
cp $SRC/Package.swift Package.swift
swift build -c debug -Xswiftc -sanitize=fuzzer,address -Xswiftc -parse-as-library -Xswiftc -static-stdlib -Xcc="-fsanitize=fuzzer-no-link,address"
cp .build/x86_64-unknown-linux-gnu/debug/*fuzz $OUT/

cp $SRC/fuzzing/dictionaries/http.dict $OUT/swift-nio-http1-fuzz.dict
