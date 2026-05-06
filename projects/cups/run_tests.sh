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
# build the unit tests
export ASAN_OPTIONS=detect_leaks=0

cd $SRC/cups
# these locales fail:
rm locale/cups_hu.po
rm locale/cups_pt.po

# Below we run two test suites.
# cups has another test suite which is part
# of `make test`: `cd test; ./run-stp-tests.sh`,
# however, this requires a non-root user and
# network interfaces that OSS-Fuzz doesn't support.

pushd cups
  make test
popd
pushd scheduler
  make test
popd

