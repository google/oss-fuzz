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

$SRC/build_cryptofuzz.sh

cd $SRC/bitcoin-core/

# Build dependencies
# This will also force static builds
if [ "$ARCHITECTURE" = "i386" ]; then
  export BUILD_TRIPLET="i686-pc-linux-gnu"
else
  export BUILD_TRIPLET="x86_64-pc-linux-gnu"
fi
(
  cd depends
  sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./funcs.mk  # Keep extracted source
  make HOST=$BUILD_TRIPLET NO_QT=1 NO_BDB=1 NO_ZMQ=1 NO_UPNP=1 NO_NATPMP=1 libevent_cflags="${CFLAGS}" sqlite_cflags="${CFLAGS}" -j$(nproc)
  # DEBUG=1 is temporarily disabled due to libc++ bugs
)

# Build the fuzz targets

sed -i "s|PROVIDE_FUZZ_MAIN_FUNCTION|NEVER_PROVIDE_MAIN_FOR_OSS_FUZZ|g" "./configure.ac"
./autogen.sh

# Temporarily compile with O2 to work around clang-13 (and later) UBSan
# -fsanitize=vptr,object-size false positive that only happens with -O1
# Fixed in https://github.com/llvm/llvm-project/commit/bbeaf2aac678
# However, OSS-Fuzz is stuck on a buggy clang, so the workaround is still
# needed. See https://github.com/google/oss-fuzz/pull/7140
if [ "$SANITIZER" = "undefined" ]; then
  export CFLAGS="$CFLAGS -O2"
  export CXXFLAGS="$CXXFLAGS -O2"
fi

# OSS-Fuzz will provide CC, CXX, etc. So only set:
# * --enable-fuzz, see https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md
# * CONFIG_SITE, see https://github.com/bitcoin/bitcoin/blob/master/depends/README.md
if [ "$SANITIZER" = "memory" ]; then
  CONFIG_SITE="$PWD/depends/$BUILD_TRIPLET/share/config.site" ./configure --with-seccomp=no --enable-fuzz SANITIZER_LDFLAGS="$LIB_FUZZING_ENGINE" --disable-hardening --with-asm=no
else
  CONFIG_SITE="$PWD/depends/$BUILD_TRIPLET/share/config.site" ./configure --with-seccomp=no --enable-fuzz SANITIZER_LDFLAGS="$LIB_FUZZING_ENGINE"
fi


if [ "$SANITIZER" = "memory" ]; then
  # MemorySanitizer (MSAN) does not support tracking memory initialization done by
  # using the Linux getrandom syscall. Avoid using getrandom by undefining
  # HAVE_SYS_GETRANDOM. See https://github.com/google/sanitizers/issues/852 for
  # details.
  grep -v HAVE_SYS_GETRANDOM src/config/bitcoin-config.h > src/config/bitcoin-config.h.tmp
  mv src/config/bitcoin-config.h.tmp src/config/bitcoin-config.h
fi

make -j$(nproc)

WRITE_ALL_FUZZ_TARGETS_AND_ABORT="/tmp/a" "./src/test/fuzz/fuzz" || true
readarray FUZZ_TARGETS < "/tmp/a"
if [ -n "${OSS_FUZZ_CI-}" ]; then
  # When running in CI, check the first targets only to save time and disk space
  FUZZ_TARGETS=( ${FUZZ_TARGETS[@]:0:2} )
fi

# OSS-Fuzz requires a separate and self-contained binary for each fuzz target.
# To inject the fuzz target name in the finished binary, compile the fuzz
# executable with the name of the fuzz target injected into the source code.
for fuzz_target in ${FUZZ_TARGETS[@]}; do
  git checkout --                                                                       "./src/test/fuzz/fuzz.cpp"
  sed -i "s|static std::string_view g_fuzz_target;|static std::string g_fuzz_target;|g" "./src/test/fuzz/fuzz.cpp"
  sed -i "s|std::getenv(\"FUZZ\")|\"$fuzz_target\"|g"                                   "./src/test/fuzz/fuzz.cpp"
  sed -i "s|.find(g_fuzz_target)|.find(g_fuzz_target.c_str())|g"                        "./src/test/fuzz/fuzz.cpp"
  make -j$(nproc)
  mv './src/test/fuzz/fuzz' "$OUT/$fuzz_target"

  chmod +x "$OUT/$fuzz_target"
  (
    cd assets/fuzz_seed_corpus
    if [ -d "$fuzz_target" ]; then
      zip --recurse-paths --quiet --junk-paths "$OUT/${fuzz_target}_seed_corpus.zip" "${fuzz_target}"
    fi
  )
done
