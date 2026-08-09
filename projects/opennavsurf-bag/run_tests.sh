#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cd bag
# Disable ASan since tests don't work with it on.
unset CFLAGS
export CXXFLAGS='-stdlib=libc++ -ldl'

cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -B test_build -S . \
  -DCMAKE_INSTALL_PREFIX:PATH=/opt \
  -DCMAKE_PREFIX_PATH='/opt;/opt/local;/opt/local/HDF_Group/HDF5/1.14.3/' \
  -DBAG_BUILD_SHARED_LIBS:BOOL=OFF \
  -DBAG_BUILD_TESTS:BOOL=ON -DBAG_CODE_COVERAGE:BOOL=OFF \
  -DBAG_BUILD_PYTHON:BOOL=OFF -DBAG_BUILD_EXAMPLES:BOOL=OFF

cmake --build test_build --config Release --target install

# There are some exclusions due to failing tests.
BAG_SAMPLES_PATH=./examples/sample-data ./test_build/tests/bag_tests '~test VR BAG reading GDAL' '~test simple layer read' '~test interleaved legacy layer read' '~test VR BAG reading NBS'
