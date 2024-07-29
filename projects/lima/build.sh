#!/bin/bash -eu
# Copyright 2024 Google LLC
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

printf "package store\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/lima/pkg/store/register.go
go mod tidy
compile_native_go_fuzzer github.com/lima-vm/lima/pkg/store FuzzLoadYAMLByFilePath FuzzLoadYAMLByFilePath
compile_native_go_fuzzer github.com/lima-vm/lima/pkg/store FuzzInspect FuzzInspect
compile_native_go_fuzzer github.com/lima-vm/lima/pkg/nativeimgutil FuzzConvertToRaw FuzzConvertToRaw
compile_native_go_fuzzer github.com/lima-vm/lima/pkg/cidata FuzzSetupEnv FuzzSetupEnv
compile_native_go_fuzzer github.com/lima-vm/lima/pkg/iso9660util FuzzIsISO9660 FuzzIsISO9660
compile_native_go_fuzzer github.com/lima-vm/lima/pkg/guestagent/procnettcp FuzzParse FuzzParse
compile_native_go_fuzzer github.com/lima-vm/lima/pkg/yqutil FuzzEvaluateExpression FuzzEvaluateExpression
compile_native_go_fuzzer github.com/lima-vm/lima/pkg/downloader FuzzDownload FuzzDownload
