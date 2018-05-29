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

./configure                             \
    --enable-fuzz-targets               \
    --enable-application-coap           \
    --enable-border-router              \
    --enable-cert-log                   \
    --enable-channel-monitor            \
    --enable-child-supervision          \
    --enable-commissioner               \
    --enable-dhcp6-client               \
    --enable-dhcp6-server               \
    --enable-dns-client                 \
    --enable-diag                       \
    --enable-dns-client                 \
    --enable-jam-detection              \
    --enable-joiner                     \
    --enable-legacy                     \
    --enable-mac-filter                 \
    --enable-mtd-network-diagnostic     \
    --enable-raw-link-api               \
    --enable-service                    \
    --enable-tmf-proxy                  \
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
