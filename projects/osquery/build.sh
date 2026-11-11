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

PROJECT=osquery

# Ensure xlocale.h is found.
ln -s /usr/include/locale.h /usr/include/xlocale.h

# Move the project content into the current overlay.
# CMake builtin 'rename' will attempt a hardlink.
( cd / &&\
  mv "${SRC}/${PROJECT}" "${SRC}/${PROJECT}-dev" &&\
  mv "${SRC}/${PROJECT}-dev" "${SRC}/${PROJECT}" )

pushd "${SRC}/${PROJECT}"

# osquery ships a Boost-MPL workaround header (mpl_static_cast_fix.hpp) for the
# Clang 16+ "static_cast<Enum>() is not a constant expression" failure in
# boost::numeric, but force-includes it only on macOS. The OSS-Fuzz Ubuntu-24.04
# base-builder uses mainline Clang 22, where this is a hard error on Linux too
# (the -Wno-enum-constexpr-conversion it already sets on Linux only covers the
# warning form). Extend the force-include guard to Linux. (Only one standalone
# `if(PLATFORM_MACOS)` exists; line 789 is an `elseif` and is not matched.)
sed -i 's/^  if(PLATFORM_MACOS)$/  if(PLATFORM_MACOS OR PLATFORM_LINUX)/' \
    libraries/cmake/source/boost/CMakeLists.txt

# That fix header is C++ (namespaces/templates) and is force-included into every
# boost-mpl consumer. On Linux a few of those are C translation units (e.g.
# osquery/tables/networking/linux/iptc_proxy.c), which don't exist on macOS.
# Guard the header so it is a no-op when compiled as C.
sed -i '/^#pragma once$/a #ifdef __cplusplus' \
    libraries/cmake/source/boost/mpl_static_cast_fix.hpp
echo '#endif /* __cplusplus */' >> libraries/cmake/source/boost/mpl_static_cast_fix.hpp

# Upstream TSK's tsk/img/raw.c now calls get_size_of_file_on_disk(), which is
# defined in tsk/util/file_system_utils.c. osquery's vendored CMake builds the
# img and util sources as separate static libraries with only a util->img
# dependency, so the final harness link fails with
# "undefined reference to get_size_of_file_on_disk". Add the reverse edge;
# CMake permits cyclic dependencies between static libraries and orders the
# link so both directions resolve.
echo 'target_link_libraries(thirdparty_sleuthkit_img PRIVATE thirdparty_sleuthkit_util)' \
  >> libraries/cmake/source/sleuthkit/CMakeLists.txt

# Ubuntu 24.04 / glibc 2.32+ removed <sys/sysctl.h> and the sysctl() libc
# function (the binary sysctl syscall is also gone from modern Linux kernels).
# osquery's Linux sysctl table already reads /proc/sys for every value; only the
# vestigial MIB/oid lookup used the removed function. Pull CTL_MAXNAME from the
# kernel UAPI header <linux/sysctl.h> on Linux, and neutralise the dead oid path.
sed -i 's@^#include <sys/sysctl.h>@#if defined(__linux__)\n#include <linux/sysctl.h>\n#else\n#include <sys/sysctl.h>\n#endif@' \
    osquery/tables/system/posix/sysctl_utils.h
sed -i '/^#include <sys\/sysctl.h>$/d' \
    osquery/tables/system/linux/sysctl_utils.cpp
sed -i 's@^  if (sysctl(oid, oid_size, response, &response_size, 0, 0) != 0) {@  (void)response;\n  (void)response_size;\n  // The binary sysctl() interface was removed from Linux and glibc 2.32+;\n  // MIB/oid-based lookups are unavailable (the /proc/sys path is used instead).\n  if (true) {@' \
    osquery/tables/system/linux/sysctl_utils.cpp

mkdir build && pushd build

cmake \
  -DOSQUERY_VERSION:string=0.0.0-fuzz \
  -DOSQUERY_ENABLE_ADDRESS_SANITIZER:BOOL=ON \
  -DOSQUERY_BUILD_FUZZERS:BOOL=ON \
  -DOSQUERY_BUILD_AWS:BOOL=OFF \
  -DOSQUERY_BUILD_EXPERIMENTS:BOOL=OFF \
  -DOSQUERY_ENABLE_CCACHE:BOOL=OFF \
  ..

cmake \
  "-DCMAKE_EXE_LINKER_FLAGS=${LIB_FUZZING_ENGINE} -Wl,-rpath,'\$ORIGIN/lib'" \
  ..

# Fix circular definitions
# See: https://github.com/osquery/osquery/issues/6551
sed -i 's/AUDIT_FILTER_EXCLUDE/AUDIT_FILTER_EXCLUDE1/g' /src/osquery/libraries/cmake/source/libaudit/src/lib/libaudit.h

# Build harnesses
cmake --build . -j$(nproc) --target osqueryfuzz-config
cmake --build . -j$(nproc) --target osqueryfuzz-sqlquery

# Cleanup
find . -type f -name '*.o' -delete
rm -rf "${SRC}/${PROJECT}/libraries/cmake/source/libudev/src/test"
rm -rf libs/src/patched-source/libudev/src/test

# Move libunwind to output path
mkdir -p "${OUT}/lib"
cp /usr/lib/x86_64-linux-gnu/libunwind.so.8 "${OUT}/lib"

# Move harnesses to output path
cp osquery/main/harnesses/osqueryfuzz-config "${OUT}/osqueryfuzz-config"
cp osquery/main/harnesses/osqueryfuzz-sqlquery "${OUT}/osqueryfuzz-sqlquery"

# Build supporting files
popd
tools/harnesses/osqueryfuzz_config_corpus.sh "${OUT}/osqueryfuzz-config_seed_corpus.zip"
tools/harnesses/osqueryfuzz_config_dict.sh "${OUT}/osqueryfuzz-config.dict"
tools/harnesses/osqueryfuzz_sqlquery_corpus.sh "${OUT}/osqueryfuzz-sqlquery_seed_corpus.zip"
cp tools/harnesses/osqueryfuzz_sqlquery.dict "${OUT}/osqueryfuzz-sqlquery.dict"
