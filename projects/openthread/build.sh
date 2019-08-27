#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

./bootstrap

export CPPFLAGS="                                     \
    -DOPENTHREAD_CONFIG_BORDER_AGENT_ENABLE=1         \
    -DOPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE=1        \
    -DOPENTHREAD_CONFIG_CHANNEL_MANAGER_ENABLE=1      \
    -DOPENTHREAD_CONFIG_CHANNEL_MONITOR_ENABLE=1      \
    -DOPENTHREAD_CONFIG_CHILD_SUPERVISION_ENABLE=1    \
    -DOPENTHREAD_CONFIG_COAP_API_ENABLE=1             \
    -DOPENTHREAD_CONFIG_COAP_SECURE_API_ENABLE=1      \
    -DOPENTHREAD_CONFIG_COMMISSIONER_ENABLE=1         \
    -DOPENTHREAD_CONFIG_DHCP6_CLIENT_ENABLE=1         \
    -DOPENTHREAD_CONFIG_DHCP6_SERVER_ENABLE=1         \
    -DOPENTHREAD_CONFIG_DIAG_ENABLE=1                 \
    -DOPENTHREAD_CONFIG_DNS_CLIENT_ENABLE=1           \
    -DOPENTHREAD_CONFIG_ECDSA_ENABLE=1                \
    -DOPENTHREAD_CONFIG_LEGACY_ENABLE=1               \
    -DOPENTHREAD_CONFIG_JAM_DETECTION_ENABLE=1        \
    -DOPENTHREAD_CONFIG_JOINER_ENABLE=1               \
    -DOPENTHREAD_CONFIG_LINK_RAW_ENABLE=1             \
    -DOPENTHREAD_CONFIG_MAC_FILTER_ENABLE=1           \
    -DOPENTHREAD_CONFIG_NCP_UART_ENABLE=1             \
    -DOPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE=1     \
    -DOPENTHREAD_CONFIG_SNTP_CLIENT_ENABLE=1          \
    -DOPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE=1  \
    -DOPENTHREAD_CONFIG_TMF_NETWORK_DIAG_MTD_ENABLE=1 \
    -DOPENTHREAD_CONFIG_UDP_FORWARD_ENABLE=1"

./configure                             \
    --enable-fuzz-targets               \
    --enable-cli                        \
    --enable-ftd                        \
    --enable-joiner                     \
    --enable-ncp                        \
    --disable-docs

make -j$(nproc)

find . -name '*-fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*-fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*-fuzzer.options' -exec cp -v '{}' $OUT ';'

fuzzers=$(find tests/fuzz -name "*-fuzzer")
for f in $fuzzers; do
    fuzzer=$(basename $f -fuzzer)

    if [ -d "tests/fuzz/corpora/${fuzzer}" ]; then
	zip -j $OUT/$(basename $f)_seed_corpus.zip tests/fuzz/corpora/${fuzzer}/*
    fi
done
