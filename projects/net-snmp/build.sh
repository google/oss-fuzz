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
./configure --with-openssl=/usr --with-defaults --with-logfile="/dev/null" --with-persistent-directory="/dev/null"
# net-snmp build is not parallel-make safe; do not add -j
make

# build fuzzers (remember to link statically)
fuzzers=(
    agentx_parse
    parse_octet_hint
    read_objid
    snmp_mib
    snmp_parse
    snmp_parse_oid
    snmp_pdu_parse
    snmp_scoped_pdu_parse
)
for fuzzname in "${fuzzers[@]}"; do
  $CC $CFLAGS -c -Iinclude -Iagent/mibgroup/agentx $SRC/${fuzzname}_fuzzer.c -o $WORK/${fuzzname}_fuzzer.o
  $CXX $CXXFLAGS $WORK/${fuzzname}_fuzzer.o \
        $LIB_FUZZING_ENGINE snmplib/.libs/libnetsnmp.a \
        agent/.libs/libnetsnmpagent.a \
        -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -lm \
        -o $OUT/${fuzzname}_fuzzer
done
