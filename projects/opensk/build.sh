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
if [ "$SANITIZER" = "coverage" ]
then
    exit 0 
fi

cd OpenSK
cargo fuzz build

# Copy fuzzers to out
cp ./fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_process_ctap1 $OUT/
cp ./fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_process_ctap2_client_pin $OUT/
cp ./fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_process_ctap2_get_assertion $OUT/
cp ./fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_process_ctap2_make_credential $OUT/
cp ./fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_process_ctap_command $OUT/
cp ./fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_split_assemble $OUT/
cp ./fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_process_ctap1 $OUT/
