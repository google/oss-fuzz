#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Dont build tests we do not care about
echo "" > ./proxygen/httpclient/samples/CMakeLists.txt
echo "" > ./proxygen/httpserver/tests/CMakeLists.txt
echo "" > ./proxygen/lib/http/structuredheaders/test/CMakeLists.txt
echo "" > ./proxygen/httpserver/filters/tests/CMakeLists.txt
echo "" > ./proxygen/lib/http/session/test/CMakeLists.txt
echo "" > ./proxygen/lib/http/codec/compress/test/CMakeLists.txt
echo "" > ./proxygen/lib/services/test/CMakeLists.txt

cd proxygen

# Link to, and copy over, libunwind
# We need to link to libunwind to ensure exception handling works
# See https://clang.llvm.org/docs/Toolchain.html#unwind-library
export LDFLAGS="-lunwind"
mkdir -p $OUT/lib
cp /usr/lib/x86_64-linux-gnu/libunwind.so.8 $OUT/lib/

# Build everything
./build.sh -m --no-install-dependencies --build-for-fuzzing

# Patch rpath so fuzzers can find libunwind
find ./_build/proxygen/fuzzers -type f -executable -exec patchelf --set-rpath '$ORIGIN/lib' {} \;

# Copy fuzzers over to the destination
find ./_build/proxygen/fuzzers -type f -executable -exec cp {} $OUT/ \;
