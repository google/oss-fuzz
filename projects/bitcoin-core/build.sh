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

# Print date to embed it into build logs
date

cd $SRC/bitcoin-core/

# Build dependencies
# This will also force static builds
if [ "$ARCHITECTURE" = "i386" ]; then
  export BUILD_TRIPLET="i386-linux-gnu"
else
  export BUILD_TRIPLET="x86_64-pc-linux-gnu"
fi

# Build using ThinLTO, to avoid OOM, and other LLVM issues.
# See https://github.com/google/oss-fuzz/pull/10123.
# Skip CFLAGS for now, to avoid:
# "/usr/bin/ld: error: Failed to link module lib/libevent.a.llvm.17822.buffer.c: Expected at most one ThinLTO module per bitcode file".
# export CFLAGS="$CFLAGS -flto=thin"
# Skip CXXFLAGS for now, to avoid: undefined reference to __sancov_gen_.
# export CXXFLAGS="$CXXFLAGS -flto=thin"
# export LDFLAGS="-flto=thin"

export CPPFLAGS="-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG -DBOOST_MULTI_INDEX_ENABLE_SAFE_MODE"

(
  cd depends
  sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./funcs.mk  # Keep extracted source
  make HOST=$BUILD_TRIPLET DEBUG=1 NO_QT=1 NO_ZMQ=1 NO_USDT=1 \
       AR=llvm-ar NM=llvm-nm RANLIB=llvm-ranlib STRIP=llvm-strip \
       -j$(nproc)
)

# Build the fuzz targets

sed -i "s|PROVIDE_FUZZ_MAIN_FUNCTION|NEVER_PROVIDE_MAIN_FOR_OSS_FUZZ|g" "./src/test/fuzz/util/CMakeLists.txt"

# OSS-Fuzz will provide CC, CXX, etc. So only set:
# * -DBUILD_FOR_FUZZING=ON, see https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md
# * --toolchain, see https://github.com/bitcoin/bitcoin/blob/master/depends/README.md
EXTRA_BUILD_OPTIONS=
if [ "$SANITIZER" = "memory" ]; then
  # _FORTIFY_SOURCE is not compatible with MSAN.
  EXTRA_BUILD_OPTIONS="-DAPPEND_CPPFLAGS='-U_FORTIFY_SOURCE'"
fi

cmake -B build_fuzz \
  --toolchain depends/${BUILD_TRIPLET}/toolchain.cmake \
  `# Setting these flags to an empty string ensures that the flags set by an OSS-Fuzz environment remain unaltered` \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="" \
  -DBUILD_FOR_FUZZING=ON \
  -DFUZZ_LIBS="$LIB_FUZZING_ENGINE" \
  $EXTRA_BUILD_OPTIONS

cmake --build build_fuzz -j$(nproc)

WRITE_ALL_FUZZ_TARGETS_AND_ABORT="/tmp/a" "./build_fuzz/bin/fuzz" || true
readarray FUZZ_TARGETS < "/tmp/a"
if [ -n "${OSS_FUZZ_CI-}" ]; then
  # When running in CI, check the first targets only to save time and disk space
  FUZZ_TARGETS=( ${FUZZ_TARGETS[@]:0:2} )
fi

# OSS-Fuzz requires a separate and self-contained binary for each fuzz target.
# To inject the fuzz target name in the finished binary, compile the fuzz
# executable with a "magic string" as the name of the fuzz target.
#
# An alternative to mocking the string in the finished binary would be to
# replace the string in the source code and re-invoke 'cmake --build'. This is slower,
# so use the hack.
export MAGIC_STR="b5813eee2abc9d3358151f298b75a72264ffa119d2f71ae7fefa15c4b70b4bc5b38e87e3107a730f25891ea428b2b4fabe7a84f5bfa73c79e0479e085e4ff157"
sed -i "s|std::getenv(\"FUZZ\")|\"$MAGIC_STR\"|g" "./src/test/fuzz/fuzz.cpp"
cmake --build build_fuzz -j$(nproc)

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

cp assets/fuzz_dicts/*.dict $OUT/
