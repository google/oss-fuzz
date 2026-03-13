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
###############################################################################

export HOST=nss
export DOMSUF=local


# The below are a subset of the tests available. This is because other tests
# fail in the OSS-Fuzz environment. Ideally all tests should be enabled.
cd tests/
#NSS_TESTS=ssl_gtests ./all.sh
export GTESTS="base_gtest certhigh_gtest certdb_gtest der_gtest util_gtest sysinit_gtest smime_gtest"
NSS_TESTS=gtests ./all.sh
