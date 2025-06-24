#!/bin/bash -eu
# Copyright 2025 Google LLC
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


# This script is useful for OSS-Fuzz infrastructure which is used to rebuild
# code from cached images. This is to support various ongoing efforts in
# OSS-Fuzz.

export FUZZ_INTROSPECTOR_CONFIG=$SRC/openssl/fuzz/fuzz_introspector_exclusion.config

function build_fuzzers() {
    SUFFIX=$1
    make -j$(nproc) LDCMD="$CXX $CXXFLAGS"

    fuzzers=$(find fuzz -executable -type f '!' -name \*.py '!' -name \*-test '!' -name \*.pl '!' -name \*.sh)
    for f in $fuzzers; do
        fuzzer=$(basename $f)
        cp $f $OUT/${fuzzer}${SUFFIX}
    done
}

cd $SRC/openssl/
build_fuzzers ""

# We only build in head, and not various versions in replay mode. Leaving the
# below commented out to make this explicit.
# cd $SRC/openssl30/
# build_fuzzers "_30"
# cd $SRC/openssl31/
# build_fuzzers "_31"
# cd $SRC/openssl32/
# build_fuzzers "_32"
