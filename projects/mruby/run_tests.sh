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
# Both test runners exit non-zero when a test fails, so `set -e` is the whole
# gate; there is nothing to parse.
#
# The batches run as two separate tasks rather than via `rake test`, which
# depends on test:build and may decide to relink. Sanitizer flags are only in
# $CFLAGS while OSS-Fuzz's `compile` runs, so a relink here would fail on
# undefined __asan_* symbols. Building is build.sh's job; these tasks only run.
#
# Requires no network access.

(
cd $SRC/mruby
rake test:run:lib
rake test:run:bin
)
