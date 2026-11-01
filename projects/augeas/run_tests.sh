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

# Disable leak sanitizer/null return check and run unit testing
export ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1"

# We are in $SRC/augeas
cd $SRC/augeas

# Run tests in the tests directory only, to avoid finicky gnulib tests
# that might fail under ASAN.
set +e
make check -j$(nproc) -C tests
test_status=$?

exit $test_status
