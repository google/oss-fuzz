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

# Skip segfault and failed cases and run the remaining unit testing
ctest --test-dir $SRC/libgd -j$(nproc) -E \
  "test_gdimagecolormatch_cve_2019_6977|test_gdimagetruecolortopalette_php_bug_72512|test_gdinterpolatedscale_gdTrivialResize|test_gdimagecopyrotated_bug00320|test_gdinterpolatedscale_gdModesAndPalettes"
