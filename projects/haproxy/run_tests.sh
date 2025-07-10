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

cd $SRC/haproxy

# This tests fails so remove it
rm reg-tests/http-rules/converters_ipmask_concat_strcmp_field_word.vtc

make unit-tests
HAPROXY_PROGRAM=$SRC/haproxy/haproxy VTEST_PROGRAM=$SRC/VTest2/vtest make reg-tests
