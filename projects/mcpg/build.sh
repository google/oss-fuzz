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

# The harness and the actual build recipe live in the upstream repo
# (.clusterfuzzlite/), shared with its ClusterFuzzLite CI, so there is a
# single source of truth. The recipe globs $SRC/*_fuzzer.py (maxdepth 1).
cp "$SRC"/mcpg/.clusterfuzzlite/*_fuzzer.py "$SRC"/
cd "$SRC"/mcpg
bash .clusterfuzzlite/build.sh
