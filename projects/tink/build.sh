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

cd cc/fuzzing && cmake .
make -j$(nproc)
mv tink_encrypt_fuzzer $OUT/

# Hack to get coverage to work. We need this due to /src/tink/cc/fuzzing/tink/__include_alias/tink
# being an symbolic link. Instead, we exchange it with the actual contents.
rm /src/tink/cc/fuzzing/tink/__include_alias/tink
mkdir /src/tinktmp
cp -rf /src/tink/cc/ /src/tinktmp/tink
cp -rf /src/tinktmp/tink/ /src/tink/cc/fuzzing/tink/__include_alias/tink
