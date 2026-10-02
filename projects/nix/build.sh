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

PREFIX="$WORK/prefix"
rm -rf \
  "$PREFIX" \
  "$WORK/blake3-build" \
  "$WORK/boost_1_87_0" \
  "$WORK/curl-build" \
  "$WORK/libstore-build" \
  "$WORK/libstore-tests-build" \
  "$WORK/libutil-build" \
  "$WORK/libutil-tests-build"
mkdir -p "$PREFIX"

for linker in gold lld bfd; do
  if [[ " $CFLAGS " == *" -fuse-ld=$linker "* ]]; then
    export CFLAGS="${CFLAGS//-fuse-ld=$linker/}"
    export CC_LD="$linker"
  fi
  if [[ " $CXXFLAGS " == *" -fuse-ld=$linker "* ]]; then
    export CXXFLAGS="${CXXFLAGS//-fuse-ld=$linker/}"
    export CXX_LD="$linker"
  fi
done

export LDFLAGS="-L$PREFIX/lib -L$PREFIX/lib64 ${LDFLAGS:-}"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PREFIX/lib64/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CMAKE_PREFIX_PATH="$PREFIX${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
export BOOST_ROOT="$PREFIX"
export BOOST_INCLUDEDIR="$PREFIX/include"
export BOOST_LIBRARYDIR="$PREFIX/lib"

cmake -S "$SRC/blake3/c" -B "$WORK/blake3-build" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DBLAKE3_SIMD_TYPE=none \
  -DBLAKE3_USE_TBB=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF
cmake --build "$WORK/blake3-build" --parallel
cmake --install "$WORK/blake3-build"

cmake -S "$SRC/curl" -B "$WORK/curl-build" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DBUILD_CURL_EXE=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DCURL_BROTLI=OFF \
  -DCURL_USE_LIBPSL=OFF \
  -DCURL_USE_OPENSSL=OFF \
  -DCURL_ZLIB=OFF \
  -DCURL_ZSTD=OFF \
  -DHTTP_ONLY=ON
cmake --build "$WORK/curl-build" --parallel
cmake --install "$WORK/curl-build"

tar -xf "$SRC/boost_1_87_0.tar.bz2" -C "$WORK"
pushd "$WORK/boost_1_87_0"
./bootstrap.sh \
  --with-libraries=context,container,coroutine,iostreams,url \
  --with-toolset=clang
cat > user-config.jam <<EOF
using clang : ossfuzz : $CXX :
  <compileflags>"$CXXFLAGS"
  <linkflags>"$CXXFLAGS $LDFLAGS"
;
EOF
./b2 \
  --user-config=user-config.jam \
  --toolset=clang-ossfuzz \
  --prefix="$PREFIX" \
  --with-context \
  --with-container \
  --with-coroutine \
  --with-iostreams \
  --with-url \
  -j"$(nproc)" \
  address-model=64 \
  link=static \
  runtime-link=shared \
  threading=multi \
  variant=release \
  install
popd

meson_setup() {
  local source_dir=$1
  local build_dir=$2
  shift 2

  meson setup "$build_dir" "$source_dir" \
    --buildtype=plain \
    --libdir=lib \
    --prefix="$PREFIX" \
    --wrap-mode=nodownload \
    -Db_lto=false \
    -Db_pch=false \
    -Ddefault_library=static \
    -Dprefer_static=true \
    "-Dcpp_args=$CXXFLAGS" \
    "-Dcpp_link_args=$CXXFLAGS $LDFLAGS" \
    "$@"
}

meson_setup "$SRC/nix/src/libutil" "$WORK/libutil-build" \
  -Dcpuid=disabled
meson compile -C "$WORK/libutil-build"
meson install -C "$WORK/libutil-build"

meson_setup "$SRC/nix/src/libstore" "$WORK/libstore-build" \
  -Dembedded-sandbox-shell=false \
  -Ds3-aws-auth=disabled \
  -Dseccomp-sandboxing=disabled
meson compile -C "$WORK/libstore-build"
meson install -C "$WORK/libstore-build"

meson_setup "$SRC/nix/src/libutil-tests" "$WORK/libutil-tests-build" \
  "-Dfuzzing-engine=$LIB_FUZZING_ENGINE" \
  -Dfuzzers=true \
  -Dunit-tests=false
meson compile -C "$WORK/libutil-tests-build" \
  fuzz-parse-dump \
  fuzz-parse-dump-case-hacked

meson_setup "$SRC/nix/src/libstore-tests" "$WORK/libstore-tests-build" \
  -Dbenchmarks=false \
  "-Dfuzzing-engine=$LIB_FUZZING_ENGINE" \
  -Dfuzzers=true \
  -Dunit-tests=false
meson compile -C "$WORK/libstore-tests-build" \
  fuzz-parse-derivation \
  fuzz-parse-derivation-experimental \
  fuzz-store-path

targets=(
  fuzz-parse-dump
  fuzz-parse-dump-case-hacked
  fuzz-parse-derivation
  fuzz-parse-derivation-experimental
  fuzz-store-path
)

cp "$WORK/libutil-tests-build/fuzz/harnesses/fuzz-parse-dump" "$OUT/"
cp "$WORK/libutil-tests-build/fuzz/harnesses/fuzz-parse-dump-case-hacked" "$OUT/"
cp "$WORK/libstore-tests-build/fuzz/harnesses/fuzz-parse-derivation" "$OUT/"
cp "$WORK/libstore-tests-build/fuzz/harnesses/fuzz-parse-derivation-experimental" "$OUT/"
cp "$WORK/libstore-tests-build/fuzz/harnesses/fuzz-store-path" "$OUT/"

zip_corpus() {
  local target=$1
  local corpus=$2

  zip -j -q "$OUT/${target}_seed_corpus.zip" "$corpus"/*
}

zip_corpus fuzz-parse-dump "$SRC/nix/src/libutil-tests/fuzz/data/nars"
cp "$OUT/fuzz-parse-dump_seed_corpus.zip" \
  "$OUT/fuzz-parse-dump-case-hacked_seed_corpus.zip"
cp "$SRC/nix/src/libutil-tests/fuzz/data/nars.dict" \
  "$OUT/fuzz-parse-dump.dict"
cp "$OUT/fuzz-parse-dump.dict" \
  "$OUT/fuzz-parse-dump-case-hacked.dict"

zip_corpus \
  fuzz-parse-derivation \
  "$SRC/nix/src/libstore-tests/fuzz/data/derivations"
cp "$OUT/fuzz-parse-derivation_seed_corpus.zip" \
  "$OUT/fuzz-parse-derivation-experimental_seed_corpus.zip"
cp "$SRC/nix/src/libstore-tests/fuzz/data/derivations.dict" \
  "$OUT/fuzz-parse-derivation.dict"
cp "$OUT/fuzz-parse-derivation.dict" \
  "$OUT/fuzz-parse-derivation-experimental.dict"

zip_corpus fuzz-store-path "$SRC/nix/src/libstore-tests/fuzz/data/store-paths"

for target in "${targets[@]}"; do
  test -x "$OUT/$target"
done
