#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

#builds project
export PATH="$HOME/.local/bin:$PATH"
$SRC/orbit/bootstrap-orbit.sh --force-public-remotes --dont-compile --ignore-system-requirements

conan profile new default --detect
conan profile update settings.compiler.libcxx=libc++ default
conan profile update settings.compiler.fpo=False default
conan profile update settings.compiler.address_sanitizer=True default
conan profile update settings.compiler.fuzzer_sanitizer=True default

sed -i 's/\[settings\]/include(libfuzzer_base)\n\n[settings]/' ~/.conan/profiles/default
echo "CFLAGS=\$BASE_CFLAGS" >> ~/.conan/profiles/default
echo "CXXFLAGS=\$BASE_CXXFLAGS" >> ~/.conan/profiles/default
echo "LDFLAGS=\$BASE_LDFLAGS" >> ~/.conan/profiles/default
echo "OrbitProfiler:CFLAGS=\$BASE_CFLAGS $CFLAGS" >> ~/.conan/profiles/default
echo "OrbitProfiler:CXXFLAGS=\$BASE_CFLAGS $CXXFLAGS" >> ~/.conan/profiles/default

# The following two lines is what should theoretically be correct. The workaround + explanation follows
# echo "llvm:CFLAGS=\$BASE_CFLAGS $CFLAGS" >> ~/.conan/profiles/default
# echo "llvm:CXXFLAGS=\$BASE_CXXFLAGS $CXXFLAGS" >> ~/.conan/profiles/default

# The $CFLAGS and $CXXFLAGS contains "-fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
# when this script is called. Since llvm currently cannot be build with address sanitizers, 
# the flags are set manually here.
echo "llvm:CFLAGS=\$BASE_CFLAGS -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION" >> ~/.conan/profiles/default
echo "llvm:CXXFLAGS=\$BASE_CXXFLAGS -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -stdlib=libc++" >> ~/.conan/profiles/default

$SRC/orbit/build.sh default

function copy_fuzzer {
  mkdir -p "$OUT/lib"
  cp -v "$1" "$OUT/"
  patchelf --set-rpath '$ORIGIN/lib' "$OUT/$(basename "$1")"

  cp -v "$SRC/default.options" "$OUT/$(basename "$1").options"

  ldd "$1" | grep '=>' | cut -d ' ' -f 3 | while read lib; do
    if [[ -f $lib ]]; then
      cp -v "$lib" "$OUT/lib/"
      patchelf --set-rpath '$ORIGIN' "$OUT/lib/$(basename "$lib")"
    fi
  done
}

find $SRC/orbit/build_default/bin -name \*Fuzzer | while read fuzzer; do
  copy_fuzzer "$fuzzer"
done
