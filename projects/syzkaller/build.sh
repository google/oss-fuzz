#!/bin/bash -eux
# Copyright 2019 Google Inc.
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



make descriptions

go mod tidy && go mod vendor

compile_go_fuzzer github.com/google/syzkaller/pkg/compiler Fuzz compiler_fuzzer
compile_go_fuzzer github.com/google/syzkaller/prog/test FuzzDeserialize prog_deserialize_fuzzer
compile_go_fuzzer github.com/google/syzkaller/prog/test FuzzParseLog prog_parselog_fuzzer
compile_go_fuzzer github.com/google/syzkaller/pkg/report Fuzz report_fuzzer

# This target is way too spammy and OOMs very quickly.
# compile_go_fuzzer ./tools/syz-trace2syz/proggen Fuzz trace2syz_fuzzer
