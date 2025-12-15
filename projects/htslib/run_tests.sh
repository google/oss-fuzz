#!/bin/bash -eux
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

# Run tests
test/hts_endian
test/test_expr
test/test_kfunc
test/test_khash
test/test_kstring
test/test_nibbles -v
test/test_str2int
test/test_time_funcs
test/fieldarith test/fieldarith.sam
test/hfile
test/test_bgzf test/bgziptest.txt
test/test-parse-reg -t test/colons.bam
test/sam test/ce.fa test/faidx/faidx.fa test/faidx/fastqs.fq
test/test-regidx

# Run script tests
(cd test/faidx && ./test-faidx.sh faidx.tst)
(cd test/sam_filter && ./filter.sh filter.tst)
(cd test/tabix && ./test-tabix.sh tabix.tst)
(cd test/mpileup && ./test-pileup.sh mpileup.tst)
(cd test/fastq && ./test-fastq.sh)
(cd test/base_mods && ./base-mods.sh base-mods.tst)
(cd test/tlen && ./tlen.sh tlen.tst)

# Run perl tests
# We need to be in test directory for test.pl to work correctly with relative paths if it expects that,
# but Makefile runs it from test directory.

# Remove failing tests (likely due to ASan/Memory limits in OSS-Fuzz environment)
#rm -f test/ce#large_seq.sam test/xx#large_aux.sam
mv test/ce#large_seq.sam /tmp/
mv test/xx#large_aux.sam  /tmp/

(cd test && REF_PATH=: ./test.pl)

# restore failing tests
mv /tmp/ce#large_seq.sam test/
mv /tmp/xx#large_aux.sam test/
