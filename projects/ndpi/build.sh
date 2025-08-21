#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

pushd $SRC/json-c-json-c-0.17-20230812
  mkdir build
  cd build
  cmake -DBUILD_SHARED_LIBS=OFF ..
  make -j$(nproc)
  make install
popd

bash -x ./ndpi/tests/ossfuzz.sh
pushd $SRC/ndpi/tests/unit
    make unit
popd
