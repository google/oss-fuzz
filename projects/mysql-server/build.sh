
#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

cd mysql-server
mkdir build
cd build
# maybe we need to add WITH_LSAN
export MY_SANITIZER="-DWITH_ASAN=ON"
if [[ $SANITIZER = *undefined* ]]; then
    export MY_SANITIZER="-DWITH_UBSAN=ON"
fi
# not handling yet WITH_MSAN nor WITH_TSAN
cmake .. -DBUILD_SHARED_LIBS=OFF -Dprotobuf_BUILD_SHARED_LIBS=OFF -DWITH_SSL=system -DCMAKE_INSTALL_PREFIX=$OUT/mysql -DWITH_LD=lld $MY_SANITIZER -DCMAKE_VERBOSE_MAKEFILE=ON
make -j$(nproc)
mkdir -p $OUT/lib/

# Copy all shared libraries that fuzzers may need
cp library_output_directory/libmysql*.so.* $OUT/lib/
# Copy harness and router libraries for router/http fuzzers
cp library_output_directory/libmysqlharness*.so.* $OUT/lib/ 2>/dev/null || true
cp library_output_directory/libmysqlrouter*.so.* $OUT/lib/ 2>/dev/null || true

# Copy all fuzzer binaries from anywhere in the build directory
find . -name "routertest_fuzz_*" -type f -executable | while read fuzzer; do
    fuzzer_name=$(basename "$fuzzer")
    cp "$fuzzer" $OUT/
    # Only run chrpath if the binary has an rpath/runpath
    if chrpath -l $OUT/$fuzzer_name 2>/dev/null | grep -q "R.*PATH"; then
        chrpath -r '$ORIGIN/lib' $OUT/$fuzzer_name
    fi
done

