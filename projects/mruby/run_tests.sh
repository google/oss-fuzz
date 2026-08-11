#!/bin/bash -eu
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
#
# mruby's test suite passes cleanly in this build, so there is nothing here to
# interpret: test/assert.rb reports success only when both KO (assertion
# failures) and Crash (tests raising an unexpected exception) are zero, and
# both test runners exit non-zero otherwise. `set -e` turns that into a failed
# run_tests.sh, which is exactly the signal Chronos needs.
#
# The two batches are invoked separately rather than through `rake test`.
# `rake test` depends on test:build, which is free to decide something needs
# relinking. The sanitizer flags exist in $CFLAGS only while OSS-Fuzz's
# `compile` is running and are not persisted into the Chronos cached image, so
# a relink here would fail on undefined __asan_* symbols. These two tasks have
# no build prerequisites and only run what build.sh already produced.
#
# No network access is required or used.

(
cd $SRC/mruby
rake test:run:lib
rake test:run:bin
)
