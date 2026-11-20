#!/bin/bash -eux
# Copyright 2025 Google LLC.
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
###############################################################################

# Offline unit tests of the project.
# Brunsli tests don't require network access.

# Run tests using ctest, showing output of failed tests.
ctest --output-on-failure

# Cleanup any artifacts to ensure idempotency.
rm -rf Testing/
# Since the build artifacts are already in the source tree from build.sh,
# we don't remove them. They are not 'new' changes in the context of run_tests.sh.
