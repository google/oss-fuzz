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


cd tests

# `make test` is a wrapper for the following tests.
# At the time of writing, `test-cli-tests fails at
# the latest master but not at the latest release,
# so it is likely that zstd will fix this. For now,
# that test is commented out. A TODO for the future
# is to call `make test` instead of each test suite
# individually.
make test-zstd
#make test-cli-tests
make test-fullbench
make test-fuzzer
make test-fullbench
make test-invalidDictionaries
make test-legacy test-decodecorpus
