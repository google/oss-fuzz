#!/bin/bash -eu
#
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

# Enter tests directory and run the v3 unit test cases. Upstream replaced the
# old tester/tester_noexcept binaries with the tester_v3_* set.
cd tests
./tester_v3_c
./tester_v3_c_v1port
./tester_v3_json_c
./tester_v3_freestanding
