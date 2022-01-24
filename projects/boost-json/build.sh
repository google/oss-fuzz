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

./bootstrap.sh --with-libraries=json

echo "using clang : ossfuzz : $CXX : <compileflags>\"$CXXFLAGS\" <linkflags>\"$CXXFLAGS\" <linkflags>\"${LIB_FUZZING_ENGINE}\" ;" >user-config.jam

./b2 --user-config=user-config.jam --toolset=clang-ossfuzz --prefix=$WORK/stage --with-json link=static install

for i in libs/json/fuzzing/*.cpp; do
   fuzzer=$(basename $i .cpp)
   $CXX $CXXFLAGS -pthread libs/json/fuzzing/$fuzzer.cpp -I $WORK/stage/include/ $WORK/stage/lib/*.a $LIB_FUZZING_ENGINE -o $OUT/$fuzzer
done

