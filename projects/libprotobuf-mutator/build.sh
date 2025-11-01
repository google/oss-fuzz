#!/bin/bash -eu
#
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

cp -f $SRC/*.dict $SRC/*.options $OUT/

mkdir -p build
pushd build
rm -rf *
cmake .. -GNinja -DCMAKE_BUILD_TYPE=Release \
    -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON \
    -DLIB_PROTO_MUTATOR_EXAMPLES_USE_LATEST=ON \
    -DLIB_PROTO_MUTATOR_FUZZER_LIBRARIES=FuzzingEngine
ninja libxml2_example expat_example
cp -f examples/libxml2/libxml2_example $OUT/
cp -f examples/expat/expat_example $OUT/
popd
