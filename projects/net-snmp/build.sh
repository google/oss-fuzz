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

sed -i 's/#define NETSNMP_SELECT_TIMEVAL ${arg_type}/#define NETSNMP_SELECT_TIMEVAL struct timeval/g' ./configure
rm testing/fuzzing/build.sh && echo "echo 0" >> testing/fuzzing/build.sh && chmod +x ./testing/fuzzing/build.sh

./configure --with-openssl=/usr --with-defaults --with-logfile="/dev/null" --with-persistent-directory="/dev/null"

# net-snmp build is not parallel-make safe; do not add -j
make

# build fuzzers and link statically
fuzzers=$(find ./testing/fuzzing -name "*_fuzzer.c")
suffix="_fuzzer\.c"
for fuzzer in ${fuzzers}; do
  fuzzname=$(basename -- ${fuzzer%$suffix})
  $CC $CFLAGS -c -Iinclude -Iagent/mibgroup/agentx ./testing/fuzzing/${fuzzname}_fuzzer.c -o $WORK/${fuzzname}_fuzzer.o
  $CXX $CXXFLAGS $WORK/${fuzzname}_fuzzer.o \
        $LIB_FUZZING_ENGINE snmplib/.libs/libnetsnmp.a \
        agent/.libs/libnetsnmpagent.a \
        -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -lm \
        -o $OUT/${fuzzname}_fuzzer
done
