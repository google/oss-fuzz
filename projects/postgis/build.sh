#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

./autogen.sh
./configure --enable-static --without-raster --without-protobuf --without-wagyu --enable-debug
cd liblwgeom
make clean -s
make -j$(nproc) -s
cd ..

bash ./fuzzers/build_google_oss_fuzzers.sh
bash ./fuzzers/build_seed_corpus.sh
