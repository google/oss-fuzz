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

# Configure and build Net-SNMP and the fuzzers.
export CC CXX CFLAGS CXXFLAGS SRC WORK OUT LIB_FUZZING_ENGINE
ci/build.sh

# Avoid leak detection atm
for fuzzer in mib agent_e2e api; do
  echo "[libfuzzer]" > $OUT/snmp_${fuzzer}_fuzzer.options
  echo "detect_leaks=0" >> $OUT/snmp_${fuzzer}_fuzzer.options
done

# Create dictionary and seeds
cp $SRC/mib.dict $OUT/snmp_mib_fuzzer.dict
zip $OUT/snmp_mib_fuzzer_seed_corpus.zip $SRC/net-snmp/mibs/*.txt
