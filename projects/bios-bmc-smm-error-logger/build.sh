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

# Remove system gtest/gmock to force using the subproject (built with libc++)
# This fixes linker errors due to ABI mismatch (libstdc++ vs libc++)
apt-get remove -y libgtest-dev libgmock-dev googletest google-mock || true
rm -rf /usr/src/googletest
rm -rf /usr/src/gtest
rm -rf /usr/src/gmock
# Ensure cmake is installed for the subproject build
apt-get update && apt-get install -y cmake

# Download subprojects explicitly so we can patch them
meson subprojects download

# Force googletest to build statically by patching its CMakeLists.txt
# This is more reliable than trying to patch test/meson.build to pass cmake options
if [ -d "subprojects/googletest" ]; then
    find subprojects/googletest -name CMakeLists.txt -exec sed -i '1i set(BUILD_SHARED_LIBS OFF CACHE BOOL "Force static" FORCE)' {} +
fi

# Fix bug in test/meson.build where 'cmake' variable is used but not defined
sed -i "s/gtest_proj = cmake.subproject(/gtest_proj = import('cmake').subproject(/g" test/meson.build

# Configure the build
# -Dtests=enabled: to build the fuzzer defined in test/meson.build
# -Ddefault_library=static: to build static libraries (good for fuzzing)
# -Dfuzz_engine: pass the fuzzing engine flags to the fuzzer executable
rm -rf build
meson setup build \
    -Dtests=enabled \
    -Ddefault_library=static \
    -Dgoogletest:default_library=static \
    -Dcpp_args="-stdlib=libc++ -Wno-error=character-conversion -Wno-error=deprecated-declarations $CXXFLAGS" \
    -Dc_args="$CFLAGS" \
    -Dcpp_link_args="${LDFLAGS:-$CXXFLAGS}" \
    -Dfuzz_engine="$LIB_FUZZING_ENGINE"

# Patch stdplus to fix missing includes and ambiguous references
if [ -f subprojects/stdplus/include/stdplus/function_view.hpp ]; then
    sed -i '1i#include <cstddef>\n#include <concepts>\n#include <type_traits>\n#include <memory>' subprojects/stdplus/include/stdplus/function_view.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/debug/lifetime.hpp ]; then
    sed -i '1i#include <cstddef>' subprojects/stdplus/include/stdplus/debug/lifetime.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/hash.hpp ]; then
    sed -i '1i#include <functional>' subprojects/stdplus/include/stdplus/hash.hpp
    # Remove conflicting forward declaration of std::hash in namespace std
    # Use ^namespace std$ to avoid matching namespace stdplus
    sed -i '/^namespace std$/,/}/ { /template <class Key>/d; /struct hash;/d; }' subprojects/stdplus/include/stdplus/hash.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/net/addr/ip.hpp ]; then
    sed -i '1i#include <format>' subprojects/stdplus/include/stdplus/net/addr/ip.hpp
    # Remove conflicting forward declaration of std::formatter
    sed -i '/template <typename T, typename CharT>/d' subprojects/stdplus/include/stdplus/net/addr/ip.hpp
    sed -i '/struct formatter;/d' subprojects/stdplus/include/stdplus/net/addr/ip.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/net/addr/subnet.hpp ]; then
    sed -i '1i#include <format>' subprojects/stdplus/include/stdplus/net/addr/subnet.hpp
    # Remove conflicting forward declaration of std::formatter
    sed -i '/template <typename T, typename CharT>/d' subprojects/stdplus/include/stdplus/net/addr/subnet.hpp
    sed -i '/struct formatter;/d' subprojects/stdplus/include/stdplus/net/addr/subnet.hpp
fi

if [ -f subprojects/stdplus/include/stdplus/str/cat.hpp ]; then
    sed -i '1i#include <algorithm>' subprojects/stdplus/include/stdplus/str/cat.hpp
fi

if [ -f subprojects/sdbusplus/include/sdbusplus/asio/connection.hpp ]; then
    sed -i 's/std::move_only_function/std::function/g' subprojects/sdbusplus/include/sdbusplus/asio/connection.hpp
fi

# Build everything
ninja -C build -v

# Copy the fuzzer to $OUT
cp build/test/rde_fuzz $OUT/
