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

pushd libsass
export BUILD='static'
make -j$(nproc)
popd

INSTALL_DIR="$SRC/libsass"

$CXX $CXXFLAGS -I${INSTALL_DIR}/include data_context_fuzzer.cc \
  $LIB_FUZZING_ENGINE -o $OUT/data_context_fuzzer ${INSTALL_DIR}/lib/libsass.a
