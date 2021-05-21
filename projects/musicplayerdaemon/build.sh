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


# Install Boost headers
(
cd $SRC/
tar jxf boost_1_74_0.tar.bz2
cd boost_1_74_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
cp -R boost/ /usr/include/
)

# build project
export CXXFLAGS="$CXXFLAGS -fuse-ld=gold"
git apply $SRC/patch.diff
if [[ $SANITIZER = *coverage* ]]; then
    meson . output/release --buildtype=debugoptimized -Db_ndebug=true -Dfuzzer=true
else
    meson . output/release --buildtype=debugoptimized -Db_ndebug=true -Dfuzzer=true -Db_sanitize=$SANITIZER
fi
ninja -C output/release
find ./output/release/test/fuzzer/ -type f -executable | while read i; do cp $i $OUT/; done
