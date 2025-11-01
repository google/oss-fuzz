#!/bin/bash -eu
# Copyright 2023 Google LLC
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

for target in $(find $SRC/skipper/fuzz/fuzz_targets -name 'Fuzz*.go'); do
        target_basename=$(basename -s .go $target)

        compile_go_fuzzer github.com/zalando/skipper/fuzz/fuzz_targets $target_basename $target_basename gofuzz
done

mv $SRC/skipper/fuzz/dictionaries/*.dict $OUT/
