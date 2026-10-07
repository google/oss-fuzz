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

# build project
autoconf
autoheader
export LDFLAGS="$CFLAGS"
./configure LIBS="-lz -lm -lbz2 -llzma -lcurl -lcrypto -lpthread"
make -j$(nproc) libhts.a bgzip htsfile tabix annot-tsv test/fuzz/hts_open_fuzzer.o

# Build tests
make -j$(nproc) test/hts_endian test/fieldarith test/hfile test/pileup test/pileup_mod \
    test/sam test/test_bgzf test/test_expr test/test_faidx test/test_kfunc \
    test/test_khash test/test_kstring test/test_mod test/test_nibbles test/test_realn \
    test/test-regidx test/test_str2int test/test_time_funcs test/test_view \
    test/test_index test/test-vcf-api test/test-vcf-sweep test/test-bcf-sr \
    test/test-bcf-translate test/test-parse-reg test/test_introspection \
    test/test-bcf_set_variant_type

# build fuzzers
$CXX $CXXFLAGS -o "$OUT/hts_open_fuzzer" test/fuzz/hts_open_fuzzer.o $LIB_FUZZING_ENGINE libhts.a -lz -lbz2 -llzma -lcurl -lcrypto -lpthread
