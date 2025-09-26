#!/bin/bash -eu
# Copyright 2025 Google LLC
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


cp fuzzservice/CMakePresets.json fuzzservice/CMakePresets_user.json
jq '.configurePresets[0].cacheVariables += {"USERVER_FEATURE_STACKTRACE":"OFF", "USERVER_FEATURE_STACK_USAGE_MONITOR":"OFF"}' fuzzservice/CMakePresets_user.json > fuzzservice/CMakePresets.json

# unset CXXFLAGS
# unset LDFLAGS

printenv

if [[ "$FUZZING_ENGINE" == "honggfuzz" ]]
then
    # cp $SRC/CMakeLists.txt $SRC/fuzzservice/CMakeLists.txt
    cp $SRC/main.cpp $SRC/fuzzservice/src/main.cpp
fi

cp $SRC/CMakeLists.txt $SRC/fuzzservice/CMakeLists.txt

cd fuzzservice
make build-debug

cp build-debug/fuzzservice $OUT/

mkdir -p $OUT/lib/
cp /usr/lib/x86_64-linux-gnu/libcctz.so.2 $OUT/lib/
cp /usr/lib/x86_64-linux-gnu/libicudata.so.66 $OUT/lib/
cp /usr/lib/x86_64-linux-gnu/libicui18n.so.66 $OUT/lib/
cp /usr/lib/x86_64-linux-gnu/libicuuc.so.66 $OUT/lib/

chrpath -r '$ORIGIN/lib' $OUT/fuzzservice