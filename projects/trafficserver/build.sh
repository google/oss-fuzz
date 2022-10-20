#!/bin/bash -eu
# Copyright 2022 Google LLC
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
export CFLAGS="$(CFLAGS)"
export CXXFLAGS="$(CFLAGS)"
export LDFLAGS="$(CFLAGS)"

autoreconf -if
./configure
make -j$(nproc)

pushd fuzzer/
make
cp FuzzEsi $OUT/FuzzEsi
popd

pushd $SRC/oss-fuzz-bloat/trafficserver/
cp  FuzzEsi_seed_corpus.zip $OUT/FuzzEsi_seed_corpus.zip
popd
