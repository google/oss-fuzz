#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cd $SRC/phosphor-host-ipmid

# Apply fuzz patch (adds fuzz_engine option to meson.options)
git apply --ignore-space-change --ignore-whitespace $SRC/fuzz-patch.diff

# Disable transport/serialbridge build (needs systemd pkg-config we don't have)
sed -i "s|subdir('transport/serialbridge')|# subdir('transport/serialbridge')|" meson.build

# Copy fuzzer source files into the test directory
cp $SRC/fuzz_*.cpp test/

# Append fuzz target definitions to test/meson.build
cat >> test/meson.build << 'MESON_EOF'

# Fuzz targets
executable(
    'fuzz_payload_unpack',
    'fuzz_payload_unpack.cpp',
    include_directories: root_inc,
    implicit_include_directories: false,
    dependencies: [
        boost,
        crypto,
        phosphor_logging_dep,
        sdbusplus_dep,
        libsystemd_dep,
    ],
    link_args: get_option('fuzz_engine').split(),
    install: true,
)

executable(
    'fuzz_fru_area',
    ['fuzz_fru_area.cpp', '../ipmi_fru_info_area.cpp'],
    include_directories: root_inc,
    implicit_include_directories: false,
    dependencies: [phosphor_logging_dep],
    link_args: get_option('fuzz_engine').split(),
    install: true,
)

executable(
    'fuzz_sensor_utils',
    'fuzz_sensor_utils.cpp',
    include_directories: root_inc,
    implicit_include_directories: false,
    dependencies: [sensorutils_dep, phosphor_logging_dep],
    link_args: get_option('fuzz_engine').split(),
    install: true,
)
MESON_EOF

# Remove boost wrap — we use system boost (libboost-all-dev), not the cmake subproject.
# meson subprojects download fails on boost.wrap since it has no meson.build.
rm -f subprojects/boost.wrap
rm -rf subprojects/boost-*

# Download meson subprojects (sdbusplus, phosphor-logging, etc.)
meson subprojects download

# stdplus is not in the wrap files but is a required dependency.
# Clone it and create a proper wrap file so meson can resolve it for all subprojects.
git clone --depth 1 https://github.com/openbmc/stdplus subprojects/stdplus
cat > subprojects/stdplus.wrap << 'WRAPEOF'
[wrap-git]
url = https://github.com/openbmc/stdplus.git
revision = HEAD

[provide]
stdplus = stdplus_dep
WRAPEOF

# Remove system gtest/gmock to force using the subproject (built with libc++)
apt-get remove -y libgtest-dev libgmock-dev googletest google-mock || true
rm -rf /usr/src/googletest /usr/src/gtest /usr/src/gmock

# Clone googletest as a subproject (remove any partial download from stdplus first)
rm -rf subprojects/googletest
git clone https://github.com/google/googletest.git --branch v1.15.2 subprojects/googletest

# Force googletest to build statically
find subprojects/googletest -name CMakeLists.txt -exec sed -i '1i set(BUILD_SHARED_LIBS OFF CACHE BOOL "Force static" FORCE)' {} +

# Configure meson
rm -rf build
meson setup build \
    -Dtests=enabled \
    -Dsoftoff=disabled \
    -Dipmi-whitelist=disabled \
    -Dlibuserlayer=disabled \
    -Ddefault_library=static \
    -Dfuzz_engine="$LIB_FUZZING_ENGINE" \
    -Dcpp_args="-stdlib=libc++ -Wno-error $CXXFLAGS" \
    -Dc_args="$CFLAGS" \
    -Dcpp_link_args="${LDFLAGS:-$CXXFLAGS}"

# ============================================================
# libc++ compatibility patches for subproject headers
# ============================================================

# stdplus patches (same fixes as bios-bmc-smm-error-logger)
if [ -f subprojects/stdplus/include/stdplus/function_view.hpp ]; then
    sed -i '1i#include <cstddef>\n#include <concepts>\n#include <type_traits>\n#include <memory>' \
        subprojects/stdplus/include/stdplus/function_view.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/debug/lifetime.hpp ]; then
    sed -i '1i#include <cstddef>' \
        subprojects/stdplus/include/stdplus/debug/lifetime.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/hash.hpp ]; then
    sed -i '1i#include <functional>' subprojects/stdplus/include/stdplus/hash.hpp
    sed -i '/^namespace std$/,/}/ { /template <class Key>/d; /struct hash;/d; }' \
        subprojects/stdplus/include/stdplus/hash.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/net/addr/ip.hpp ]; then
    sed -i '1i#include <format>' subprojects/stdplus/include/stdplus/net/addr/ip.hpp
    sed -i '/template <typename T, typename CharT>/d' subprojects/stdplus/include/stdplus/net/addr/ip.hpp
    sed -i '/struct formatter;/d' subprojects/stdplus/include/stdplus/net/addr/ip.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/net/addr/subnet.hpp ]; then
    sed -i '1i#include <format>' subprojects/stdplus/include/stdplus/net/addr/subnet.hpp
    sed -i '/template <typename T, typename CharT>/d' subprojects/stdplus/include/stdplus/net/addr/subnet.hpp
    sed -i '/struct formatter;/d' subprojects/stdplus/include/stdplus/net/addr/subnet.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/str/cat.hpp ]; then
    sed -i '1i#include <algorithm>' subprojects/stdplus/include/stdplus/str/cat.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/net/addr/ether.hpp ]; then
    sed -i '1i#include <format>' subprojects/stdplus/include/stdplus/net/addr/ether.hpp
    sed -i '/template <typename T, typename CharT>/d' subprojects/stdplus/include/stdplus/net/addr/ether.hpp
    sed -i '/struct formatter;/d' subprojects/stdplus/include/stdplus/net/addr/ether.hpp
fi
if [ -f subprojects/stdplus/include/stdplus/numeric/endian.hpp ]; then
    sed -i '1i#include <format>' subprojects/stdplus/include/stdplus/numeric/endian.hpp
    sed -i '/template <typename T, typename CharT>/d' subprojects/stdplus/include/stdplus/numeric/endian.hpp
    sed -i '/struct formatter;/d' subprojects/stdplus/include/stdplus/numeric/endian.hpp
fi

# sdbusplus patch: std::move_only_function not available in older libc++
if [ -f subprojects/sdbusplus/include/sdbusplus/asio/connection.hpp ]; then
    sed -i 's/std::move_only_function/std::function/g' \
        subprojects/sdbusplus/include/sdbusplus/asio/connection.hpp
fi

# sdbusplus patch: close() needs unistd.h with some libc++ versions
if [ -f subprojects/sdbusplus/include/sdbusplus/event.hpp ]; then
    grep -q '#include <unistd.h>' subprojects/sdbusplus/include/sdbusplus/event.hpp || \
        sed -i '1i#include <unistd.h>' subprojects/sdbusplus/include/sdbusplus/event.hpp
fi

# stdexec patch: std::launder needs <new> with libc++
if [ -d subprojects/stdexec ]; then
    find subprojects/stdexec -name '__utility.hpp' -exec \
        sed -i '1i#include <new>' {} +
fi

# boost container_hash: std::unary_function removed in C++17 with libc++
find /usr/include/boost -name hash.hpp -path '*/container_hash/*' -exec \
    sed -i 's/struct hash_base : std::unary_function<T, std::size_t>/struct hash_base/' {} + 2>/dev/null || true

# Build everything
ninja -C build -v -j$(($(nproc) / 4))

# Copy fuzzers to $OUT
cp build/test/fuzz_payload_unpack $OUT/
cp build/test/fuzz_fru_area $OUT/
cp build/test/fuzz_sensor_utils $OUT/
