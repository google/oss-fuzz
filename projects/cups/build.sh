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
export CFLAGS="$CFLAGS -fPIE"
export CXXFLAGS="$CFLAGS -fPIE"
export LDFLAGS="$CFLAGS -fPIE"

./configure --enable-static --disable-shared --with-dnssd=no
make 

pushd fuzzer/
make
cp FuzzCUPS $OUT/FuzzCUPS
cp FuzzIPP $OUT/FuzzIPP
cp FuzzRaster $OUT/FuzzRaster
popd

pushd $SRC/oss-fuzz-bloat/cups
cp FuzzCUPS_seed_corpus.zip $OUT/FuzzCUPS_seed_corpus.zip
cp FuzzIPP_seed_corpus.zip $OUT/FuzzIPP_seed_corpus.zip
cp FuzzRaster_seed_corpus.zip $OUT/FuzzRaster_seed_corpus.zip
popd
