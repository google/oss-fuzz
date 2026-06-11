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
cd $SRC/semver
cp $SRC/fuzz_test.go ./
compile_go_fuzzer github.com/Masterminds/semver/v3 FuzzVersionCompare fuzz_version_compare
compile_go_fuzzer github.com/Masterminds/semver/v3 FuzzVersionRoundTrip fuzz_version_roundtrip
compile_go_fuzzer github.com/Masterminds/semver/v3 FuzzIncOverflow fuzz_inc_overflow
compile_go_fuzzer github.com/Masterminds/semver/v3 FuzzConstraintVersionCheck fuzz_constraint_version_check
