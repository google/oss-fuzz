#!/bin/bash -eu
#
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

if [[ "$SANITIZER" == "memory" ]]
then
  # Unit test will failed on these test cases because of uninitialized memory, thus skipping them.
  ctest --test-dir $SRC/arduinojson/build-tests -j$(nproc) -E \
    "Cpp17|Cpp20|Deprecated|IntegrationTests|JsonArray|JsonArrayConst|JsonDeserializer|JsonDocument|JsonObject|JsonObjectConst|JsonSerializer|JsonVariant|JsonVariantConst|ResourceManager|Misc|MixedConfiguration|MsgPackDeserializer|MsgPackSerializer|Numbers|TextFormatter|json_fuzzer|msgpack_fuzzer"
else
  ctest --test-dir $SRC/arduinojson/build-tests -j$(nproc)
fi
