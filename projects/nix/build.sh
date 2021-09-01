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

# Provide a truly reproducible environment
#   * For build, using `nix`;
#   * And runtime, by bundling with `exodus` (https://github.com/intoli/exodus) to "extract" the binary
#     and its dependency closure out of the `/nix/store`.

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

# `nix` compilation will use `libstdc++` because we are on GNU/Linux.
export CXXFLAGS=$(echo "$CXXFLAGS" | sed -e 's/ -stdlib=libc++//g')

# We set `fuzzer_CXXFLAGS`, and `lib*_CXXFLAGS` to "inherit" the provided `CXXFLAGS`, and add some extra flags;
# Also, `fuzzer_LDFLAGS`, and `lib*_LDFLAGS` receive some extra flags.

_fuzzer_LDFLAGS='-fsanitize=fuzzer '
_lib_flags=
if [[ ! $SANITIZER = *coverage* ]]; then
  # This flag breaks the linkage of the `src/lib*/libnix*.so` when building for coverage.
  _lib_flags+='-fsanitize=fuzzer-no-link '
fi
for S in $SANITIZER; do
  if [ $SANITIZER = 'address' ]; then
    # Static `libasan` is linked by default with `clang`;
    # However, this cause 1) problems with redefinition of symbols, 2) conflicts with `-Wl,-z,defs` that `nix` uses.
    _fuzzer_LDFLAGS+='-shared-libasan '
    _lib_flags+='-shared-libasan '
  elif [ $SANITIZER = 'coverage' ]; then
    # The linkage of the libraries need the coverage instrumentation flags too (flags for the compiler are already given through `CXXFLAGS`).
    _fuzzer_LDFLAGS+="$COVERAGE_FLAGS"
    _lib_flags+="$COVERAGE_FLAGS"
    continue
  fi
  _fuzzer_LDFLAGS+="-fsanitize=$S "
  _lib_flags+="-fsanitize=$S "
done

export fuzzer_LDFLAGS=$_fuzzer_LDFLAGS
export fuzzer_CXXFLAGS="$CXXFLAGS"

for lib in src/lib*; do
  LIB="$(basename $lib)"

  export "${LIB}_CXXFLAGS"="$CXXFLAGS $_lib_flags"
  export "${LIB}_LDFLAGS"="$_lib_flags"
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
