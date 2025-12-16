#!/bin/bash -eu
# Copyright 2025 Google LLC
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

git apply  --ignore-space-change --ignore-whitespace $SRC/fuzz-patch.diff

# Configure the build
# -Dtests=enabled: to build the fuzzer defined in test/meson.build
# -Ddefault_library=static: to build static libraries (good for fuzzing)
# -Dfuzz_engine: pass the fuzzing engine flags to the fuzzer executable
rm -rf build
meson setup build \
    -Dtests=enabled \
    -Ddefault_library=static \
    -Dfuzz_engine="$LIB_FUZZING_ENGINE"

# Patch stdplus to fix missing includes
if [ -f subprojects/stdplus/include/stdplus/function_view.hpp ]; then
    sed -i '1i#include <cstddef>\n#include <concepts>\n#include <type_traits>\n#include <memory>' subprojects/stdplus/include/stdplus/function_view.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/debug/lifetime.hpp ]; then
    sed -i '1i#include <cstddef>' subprojects/stdplus/include/stdplus/debug/lifetime.hpp
fi

# Build everything
ninja -C build -v

# Copy the fuzzer to $OUT
cp build/test/rde_fuzz $OUT/
