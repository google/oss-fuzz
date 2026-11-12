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

cd "$SRC/safere"

# SafeRE owns target enrollment: safere-fuzz/targets.json marks which fuzz
# targets are OSS-Fuzz-eligible, and safere-fuzz/oss-fuzz/build.sh builds the
# runtime, launchers, dictionaries and seed corpora for exactly those targets.
exec bash safere-fuzz/oss-fuzz/build.sh
