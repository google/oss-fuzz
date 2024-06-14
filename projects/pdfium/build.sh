#!/bin/bash -eu
# Copyright 2022 Google LLC
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

cd repo/pdfium

# Disable trying to install snapcraft because this won't work in the Docker images
sed -i 's/snapcraft/snapcraftnonexisting/g' ./build/install-build-deps.sh
build/install-build-deps.sh

# Quick hack which should probably go in the base images
cp ./third_party/llvm-build/Release+Asserts/bin/llvm-readelf /usr/local/bin/llvm-readelf

cp $SRC/clang_BUILD.gn build/config/clang/BUILD.gn
cp $SRC/clang.gni build/config/clang/clang.gni

# Copy over libclang_rt.fuzzer
# This is hopefully a temporary hack. Hack is needed because the pdfium build
# forces(?) the use of clang downloaded as a third party. This should be fixed,
# however, such that we use the $CC and $CXX from oss-fuzz, in order to compile
# with honggfuzz and afl++
# NB: This is not needed anymore because we now use clang.gni and clang/BUILD.gn above.
#cp /usr/local/lib/clang/14.0.0/lib/linux/libclang_rt.fuzzer-x86_64.a ./third_party/llvm-build/Release+Asserts/lib/clang/15.0.0/lib/linux/libclang_rt.fuzzer-x86_64.a

# Copy our fuzzer updated BUILD.gn
cp $SRC/OSS_FUZZ_BUILD.gn testing/BUILD.gn

# Create appropriate flags depending on state
if [ $SANITIZER == "address" ]; then
  sed -i 's/FUZZCFLAGS/-fsanitize=fuzzer-no-link,address/g' ./testing/BUILD.gn
  sed -i 's/FUZZLDFLAGS/-fsanitize=fuzzer/g' ./testing/BUILD.gn
elif [ $SANITIZER == "coverage" ]; then
  sed -i 's/FUZZCFLAGS/-fprofile-instr-generate\", \"-fcoverage-mapping/g' ./testing/BUILD.gn
  sed -i 's/FUZZLDFLAGS/-fsanitize=fuzzer/g' ./testing/BUILD.gn
fi

# Generate configs for fuzzers
mkdir -p out/fuzzers
if [ $SANITIZER == "address" ]; then
  cp $SRC/args.gn out/fuzzers/args.gn
elif [ $SANITIZER == "coverage" ]; then
  cp $SRC/cov_args.gn out/fuzzers/args.gn
fi
gn gen out/fuzzers

ninja -v -C out/fuzzers/ pdf_cmap_fuzzer
#ninja -v -C out/fuzzers/ pdf_cmap_fuzzer
cp out/fuzzers/pdf_cmap_fuzzer $OUT/pdf_cmap_fuzzer
