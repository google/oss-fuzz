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
# The wazuh fuzzers live upstream in $SRC/wazuh/src/fuzzing and are built
# through the project's own CMake build system (WAZUH_BUILD_FUZZERS=ON).
# This script only adapts the OSS-Fuzz environment and collects the outputs.

cd $SRC/wazuh/src
export LDFLAGS="$CFLAGS"
sed -i 's/CC=gcc/CC=clang/g' Makefile

make deps TARGET=agent

mkdir -p build && cd build
cmake .. -DTARGET=agent -DWAZUH_BUILD_FUZZERS=ON
make -j$(nproc) wazuh fuzz_xml fuzz_os_regex fuzz_os_xml_access fuzz_shared_stringop fuzz_version_op fuzz_os_signature
cd ..

for f in build/fuzzing/fuzz_*; do
    [ -f "$f" ] && cp "$f" $OUT/
done

cp fuzzing/*.options $OUT/
cp fuzzing/wz_test_ca.pem $OUT/wz_test_ca.pem

find fuzzing -maxdepth 1 -name '*.dict' -exec cp {} $OUT/ \;

for CORPUS in fuzzing/*.corpus; do
    [ -d "$CORPUS" ] || continue
    BASENAME=${CORPUS##*/}
    (cd "$CORPUS" && zip -q -r $OUT/${BASENAME%%.*}_seed_corpus.zip .)
done
