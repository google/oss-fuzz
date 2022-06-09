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

mkdir -p $WORK/open62541
cd $WORK/open62541

# LOGLEVEL:
# <= 100 TRACE
# <= 200 DEBUG
# <= 300 INFO
# <= 400 WARNING
# <= 500 ERROR
# <= 600 FATAL
# > 600 No LOG output

cmake -DCMAKE_BUILD_TYPE=Debug -DUA_ENABLE_AMALGAMATION=OFF \
      -DPYTHON_EXECUTABLE:FILEPATH=/usr/bin/python2 \
      -DBUILD_SHARED_LIBS=OFF -DUA_BUILD_EXAMPLES=OFF -DUA_LOGLEVEL=600 \
      -DUA_ENABLE_ENCRYPTION=ON \
      -DUA_BUILD_OSS_FUZZ=ON \
      $SRC/open62541/

# This also builds all the fuzz targets and places them in the $OUT directory
# Only build with one process otherwise amalgamation fails.
make -j1

# Copy the corpus, dict and options to the $OUT dir
$SRC/open62541/tests/fuzz/oss-fuzz-copy.sh

echo "Built all fuzzer targets."
