#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

if [[ $SANITIZER = *coverage* ]]; then
        compile_go_fuzzer github.com/pingcap/tidb/types FuzzMarshalJSON fuzzMarshalJSON
        compile_go_fuzzer github.com/pingcap/tidb/types FuzzNewBitLiteral fuzzNewBitLiteral
        compile_go_fuzzer github.com/pingcap/tidb/types FuzzNewHexLiteral fuzzNewHexLiteral
        exit 0
fi

compile_go_fuzzer ./types FuzzMarshalJSON fuzzMarshalJSON
compile_go_fuzzer ./types FuzzNewBitLiteral fuzzNewBitLiteral
compile_go_fuzzer ./types FuzzNewHexLiteral fuzzNewHexLiteral
