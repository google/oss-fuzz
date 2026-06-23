#!/bin/bash -eu
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
################################################################################
cd $GOPATH/src/github.com/rhysmcneill/ssmctl/

go mod download
go mod tidy

compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzSanitizeBasename fuzz_sanitizebasename
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzRemoteBaseName fuzz_remotebasename
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzDownloadBase64Decoding fuzz_downloadbase64decoding
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzAllInstanceIDs fuzz_allinstanceids
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzFirstInstance fuzz_firstinstance
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzShellQuote fuzz_shellquote
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzPowerShellQuote fuzz_powershellquote
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzNoInstancesFound fuzz_noinstancesfound
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzNormalizeWindowsPath fuzz_normalizewindowspath
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzTargetInfoFromInstance fuzz_targetinfofrommodule
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzParseRemoteFlag fuzz_parseremotsflag
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzNameTag fuzz_nametag
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzParseArg fuzz_parsearg
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzParseS3URL fuzz_parses3url
compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm FuzzListInstancesFiltering fuzz_list
