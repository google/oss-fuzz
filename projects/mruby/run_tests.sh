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
################################################################################

(
export LD=$CC
export LDFLAGS="$CFLAGS"
cd $SRC/mruby
rake test > /tmp/test.out 2>&1
)

# There are two test runs, each of which executes many tests. Neither of these
# must have crashing tests and that they have successful tests as well.
# For the first batch We expect 165x tests to succeed and some tests skipped,
# and 100 for the second batch.
# I suspect the skipping causes
# rake to return an error code. However, in normal circumastances we see
# 9 tests skipped.
grep "OK: 165" /tmp/test.out
grep "OK: 100" /tmp/test.out

if [[ `grep "Crash: 0" /tmp/test.out | wc -l` != '2' ]]; then
    exit 1
fi
if [[ `grep "KO: 0" /tmp/test.out | wc -l` != '2' ]]; then
    exit 1
fi
