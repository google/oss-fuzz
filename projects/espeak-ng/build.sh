#!/bin/bash -eu
# Copyright 2021 Google LLC
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


# build project
export ASAN_OPTIONS=detect_leaks=0
./autogen.sh
./configure --with-libfuzzer=yes --disable-shared --with-speechplayer=no
make check || true
cp tests/ssml-fuzzer.test $OUT/ssml-fuzzer
cp -r espeak-ng-data/ $OUT/
