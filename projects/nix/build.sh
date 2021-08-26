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

#
# Provide a truly reproducible environment
#   * For build, using `nix`;
#   * And runtime, by bundling with `exodus` to "extract" the binary and its dependency closure out of the `/nix/store`.
#

function nixDevelop () {
  nix \
    --experimental-features "flakes nix-command" \
    develop \
    .\#.clang11StdenvPackages \
    $@
}

cd $SRC/nix

nixDevelop --command ./bootstrap.sh
nixDevelop --command ./configure \
  --enable-gc=no \
  --prefix=$OUT

make clean

_fuzzer_LDFLAGS="-fsanitize=fuzzer "
_lib_FLAGS='-fsanitize=fuzzer-no-link '
for S in $SANITIZER; do
  # Static `libasan` is linked by default with `clang`;
  # However, this cause 1) problems with redefinition of symbols, 2) conflicts with `-Wl,-z,defs` that `nix` uses.
  if [ $SANITIZER == 'address' ]; then
    _fuzzer_LDFLAGS+='-shared-libasan '
    _lib_FLAGS+='-shared-libasan '
  fi
  _fuzzer_LDFLAGS+="-fsanitize=$S "
  _lib_FLAGS+="-fsanitize=$S "
done

export fuzzer_LDFLAGS=$_fuzzer_LDFLAGS
# `nix` compilation will use `libstdc++` because we are on GNU/Linux.
export fuzzer_CXXFLAGS=$(subst -stdlib=libc++,,$CXXFLAGS)

for lib in src/lib*; do
  LIB="$(basename $lib)"

  export "${LIB}_CXXFLAGS"="$_lib_FLAGS"
  export "${LIB}_LDFLAGS"="$_lib_FLAGS"
done

export OPTIMIZE=0
export ENABLE_S3=0
export HAVE_BOEHMGC=0

nixDevelop --command make -j$(nproc) fuzz/parse_store_path
# `make install` is not enough,
# as the OSS-fuzz infrastructure does not guarantee the presence of the shared libraries (i.e. runtime dependencies).
exodus -v -o fuzzer-bundle fuzz/parse_store_path
./fuzzer-bundle $OUT

cd -
