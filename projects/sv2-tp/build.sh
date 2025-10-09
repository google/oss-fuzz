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

# Adapted from ../bitcoin-core, tailored for sv2-tp.

# Print date to embed it into build logs
date

cd "$SRC/sv2-tp"/

# Build dependencies via depends/ to keep environment consistent and prefer static libs
# Only build for 64-bit x86 on OSS-Fuzz.
export BUILD_TRIPLET="x86_64-pc-linux-gnu"

# LTO and linker selection similar to bitcoin-core setup
export CFLAGS="${CFLAGS:-} -flto=full"
export CXXFLAGS="${CXXFLAGS:-} -flto=full"
# Use lld to workaround <module> referenced in <section> of /tmp/lto-llvm-*.o: defined in discarded section
export LDFLAGS="-fuse-ld=lld -flto=full ${LDFLAGS:-}"

# Hardened libc++ to catch UB earlier
export CPPFLAGS="${CPPFLAGS:-} -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG"

(
  cd depends
  # Keep extracted sources to speed up iteration
  sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./funcs.mk || true
  # src/ipc tracks bitcoin-core, so no need to test it here
  make HOST=$BUILD_TRIPLET DEBUG=1 \
       NO_IPC=1 \
       AR=llvm-ar NM=llvm-nm RANLIB=llvm-ranlib STRIP=llvm-strip \
       -j"$(nproc)"
)

# Build the fuzz targets

sed -i "s|PROVIDE_FUZZ_MAIN_FUNCTION|NEVER_PROVIDE_MAIN_FOR_OSS_FUZZ|g" ./src/test/fuzz/CMakeLists.txt || true

# OSS-Fuzz will provide CC, CXX, etc. So only set:
#  * -DBUILD_FOR_FUZZING=ON (see doc/fuzzing.md in upstream project)
#  * --toolchain from depends/
EXTRA_BUILD_OPTIONS=
if [ "${SANITIZER:-address}" = "memory" ]; then
  # _FORTIFY_SOURCE is not compatible with MSAN.
  EXTRA_BUILD_OPTIONS="-DAPPEND_CPPFLAGS='-U_FORTIFY_SOURCE'"
fi

cmake -B build_fuzz \
  --toolchain "depends/${BUILD_TRIPLET}/toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  `# Keep OSS-Fuzz-provided flags intact:` \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="" \
  -DBUILD_FOR_FUZZING=ON \
  -DBUILD_FUZZ_BINARY=ON \
  -DFUZZ_LIBS="$LIB_FUZZING_ENGINE" \
  -DSANITIZERS="${SANITIZER:-address}" \
  $EXTRA_BUILD_OPTIONS

cmake --build build_fuzz -j"$(nproc)"

# Enumerate fuzz targets compiled into the fuzz binary
WRITE_ALL_FUZZ_TARGETS_AND_ABORT="/tmp/fuzz_targets.txt" ./build_fuzz/bin/fuzz || true
readarray -t FUZZ_TARGETS < "/tmp/fuzz_targets.txt" || FUZZ_TARGETS=()

if [ -n "${OSS_FUZZ_CI-}" ]; then
  # Trim the set to keep CI resource use low
  FUZZ_TARGETS=( ${FUZZ_TARGETS[@]:0:2} )
fi

# OSS-Fuzz requires a separate and self-contained binary for each fuzz target.
# To inject the fuzz target name in the finished binary, compile the fuzz
# executable with a "magic string" as the name of the fuzz target.
#
# An alternative to mocking the string in the finished binary would be to
# replace the string in the source code and re-invoke 'cmake --build'. This is slower,
# so use the hack.
export MAGIC_STR="d6f1a2b39c4e5d7a8b9c0d1e2f30415263748596a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00fedcba9876543210a0b1c2d3"
sed -i "s|std::getenv(\"FUZZ\")|\"$MAGIC_STR\"|g" ./src/test/fuzz/fuzz.cpp
cmake --build build_fuzz -j"$(nproc)"

# Replace the magic string with the actual name of each fuzz target
for fuzz_target in ${FUZZ_TARGETS[@]}; do
  df --human-readable ./src
  python3 -c "c_str_target=b\"${fuzz_target}\x00\";c_str_magic=b\"$MAGIC_STR\";dat=open('./build_fuzz/bin/fuzz','rb').read();dat=dat.replace(c_str_magic, c_str_target+c_str_magic[len(c_str_target):]);open(\"$OUT/$fuzz_target\",'wb').write(dat)"

  chmod +x "$OUT/$fuzz_target"
  (
    cd assets/fuzz_corpora
    if [ -d "$fuzz_target" ]; then
      zip --recurse-paths --quiet --junk-paths "$OUT/${fuzz_target}_seed_corpus.zip" "${fuzz_target}"
    fi
  )
done
