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

mkdir -p $WORK/mdnsd
cd $WORK/mdnsd

cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DMDNSD_BUILD_OSS_FUZZ=ON \
      $SRC/mdnsd/

# This also builds all the fuzz targets and places them in the $OUT directory
make -j

# Copy the corpus, dict and options to the $OUT dir
$SRC/mdnsd/tests/fuzz/oss-fuzz-copy.sh

echo "Built all fuzzer targets."
