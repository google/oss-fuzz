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

# Build using ThinLTO, to avoid OOM, and other LLVM issues.
# See https://github.com/google/oss-fuzz/pull/10123.
sed -i 's/flto/flto=thin/g' ./depends/hosts/linux.mk
sed -i 's/flto/flto=thin/g' ./configure.ac

if [ "$ARCHITECTURE" = "i386" ]; then
# Temporary workaround for building sqlite for 32-bit. Due to https://github.com/google/oss-fuzz/pull/10466#issuecomment-1576658462
sed -i 's/-D_LIBCPP_ENABLE_ASSERTIONS=1/-D_LIBCPP_ENABLE_ASSERTIONS=1 -m32/g' ./depends/hosts/linux.mk
fi

(
  cd depends
  sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./funcs.mk  # Keep extracted source
  # LTO=1 temporarily disabled due to https://github.com/google/oss-fuzz/pull/9461#issuecomment-1568189633
  make HOST=$BUILD_TRIPLET DEBUG=1 NO_QT=1 NO_BDB=1 NO_ZMQ=1 NO_UPNP=1 NO_NATPMP=1 NO_USDT=1 AR=llvm-ar RANLIB=llvm-ranlib -j$(nproc)
)

# Build the fuzz targets

sed -i "s|PROVIDE_FUZZ_MAIN_FUNCTION|NEVER_PROVIDE_MAIN_FOR_OSS_FUZZ|g" "./configure.ac"
./autogen.sh

# OSS-Fuzz will provide CC, CXX, etc. So only set:
# * --enable-fuzz, see https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md
# * CONFIG_SITE, see https://github.com/bitcoin/bitcoin/blob/master/depends/README.md
if [ "$SANITIZER" = "memory" ]; then
  CONFIG_SITE="$PWD/depends/$BUILD_TRIPLET/share/config.site" ./configure --with-seccomp=no --enable-fuzz SANITIZER_LDFLAGS="$LIB_FUZZING_ENGINE" --disable-hardening --with-asm=no
else
  CONFIG_SITE="$PWD/depends/$BUILD_TRIPLET/share/config.site" ./configure --with-seccomp=no --enable-fuzz SANITIZER_LDFLAGS="$LIB_FUZZING_ENGINE"
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
# executable with a "magic string" as the name of the fuzz target.
#
# An alternative to mocking the string in the finished binary would be to
# replace the string in the source code and re-invoke 'make'. This is slower,
# so use the hack.
export MAGIC_STR="b5813eee2abc9d3358151f298b75a72264ffa119d2f71ae7fefa15c4b70b4bc5b38e87e3107a730f25891ea428b2b4fabe7a84f5bfa73c79e0479e085e4ff157"
sed -i "s|std::getenv(\"FUZZ\")|\"$MAGIC_STR\"|g" "./src/test/fuzz/fuzz.cpp"
make -j$(nproc)

# Replace the magic string with the actual name of each fuzz target
for fuzz_target in ${FUZZ_TARGETS[@]}; do
  python3 -c "c_str_target=b\"${fuzz_target}\x00\";c_str_magic=b\"$MAGIC_STR\";dat=open('./src/test/fuzz/fuzz','rb').read();dat=dat.replace(c_str_magic, c_str_target+c_str_magic[len(c_str_target):]);open(\"$OUT/$fuzz_target\",'wb').write(dat)"

  chmod +x "$OUT/$fuzz_target"
  (
    cd assets/fuzz_seed_corpus
    if [ -d "$fuzz_target" ]; then
      zip --recurse-paths --quiet --junk-paths "$OUT/${fuzz_target}_seed_corpus.zip" "${fuzz_target}"
    fi
  )
done

cp assets/fuzz_dicts/*.dict $OUT/
