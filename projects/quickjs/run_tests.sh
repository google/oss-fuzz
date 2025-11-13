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

# At the time of writing, `tests/test_worker.js`
# fails from latest master, so we remove it.
# This is being tracked in https://github.com/bellard/quickjs/issues/390.
# A TODO is to track when it has been patched
# upstream and enable all tests.
git apply $SRC/run_tests_patch.diff
CONFIG_CLANG=y make test
git apply -R $SRC/run_tests_patch.diff
