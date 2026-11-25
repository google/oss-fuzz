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

# The repository's script builds the six fuzz targets, their dictionaries and seed corpora
# into $OUT from $CXX, $CXXFLAGS and $LIB_FUZZING_ENGINE (see docs/dev/fuzzing.md there).
# It builds the SSE2 code paths, which run on any x86-64 machine.
$SRC/OpenHTJ2K/tests/fuzz/build.sh
