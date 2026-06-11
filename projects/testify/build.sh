# Copyright 2026 Google LLC
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

#!/bin/bash -eu
cd $SRC/testify
cp $SRC/fuzz_test.go ./
compile_go_fuzzer github.com/stretchr/testify FuzzAssertEqual fuzz_assert_equal
compile_go_fuzzer github.com/stretchr/testify FuzzAssertJSON fuzz_assert_json
compile_go_fuzzer github.com/stretchr/testify FuzzAssertYAML fuzz_assert_yaml
compile_go_fuzzer github.com/stretchr/testify FuzzRequireInt fuzz_require_int
compile_go_fuzzer github.com/stretchr/testify FuzzElementsMatch fuzz_elements_match
