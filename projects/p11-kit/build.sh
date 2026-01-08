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

./autogen.sh
make -j$(nproc) oss-fuzz

cd fuzz
for dir in *.in; do
    fuzzer=$(basename $dir .in)_fuzzer
    zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "${dir}/"
done

# The build above only builds the fuzzers using autotools.
# Unit test definitions are located in meson.build.
# Build the unit test suite with meson for run_tests.sh.
# CXXFLAGS must be unset because it contains -stdlib=libc++ which is C++ specific
# and causes linker errors when building this primarily C project with meson. The
# sanitizer flags combined with C++ flags also create linking conflicts between C
# and C++ runtime libraries in the meson build system.
cd $SRC/p11-kit
CFLAGS= CXXFLAGS= meson setup build
ninja -C build
