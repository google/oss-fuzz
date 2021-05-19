#!/bin/bash -eu
# Copyright 2021 Google LLC
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

mv $SRC/sm2_fuzzer.go ./core/crypto/client/gm/gmsm/sm2

mv $SRC/smr_fuzzer.go ./core/consensus/common/chainedbft/smr/
mv ./core/consensus/common/chainedbft/smr/smr_test.go ./core/consensus/common/chainedbft/smr/smr_test_fuzz.go
compile_go_fuzzer github.com/xuperchain/xuperchain/core/crypto/client/gm/gmsm/sm2 Fuzz sm2_fuzzer
compile_go_fuzzer github.com/xuperchain/xuperchain/core/consensus/common/chainedbft/smr Fuzz safety_rule_fuzzer

