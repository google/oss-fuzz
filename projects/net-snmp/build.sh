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

# Globally disable leaks to let fuzzers continue.
export ASAN_OPTIONS="detect_leaks=0"
export CFLAGS="${CFLAGS} -Wno-error=declaration-after-statement"

# Configure and build Net-SNMP and the fuzzers.
export CC CXX CFLAGS CXXFLAGS SRC WORK OUT LIB_FUZZING_ENGINE
MODE=regular ci/build.sh

# Create dictionary and seeds
cp $SRC/mib.dict $OUT/snmp_mib_fuzzer.dict
zip $OUT/snmp_mib_fuzzer_seed_corpus.zip $SRC/net-snmp/mibs/*.txt
