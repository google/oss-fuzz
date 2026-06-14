#!/bin/bash -eu
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the Apache License, Version 2.0.
#
################################################################################

cd $GOPATH/src/ssmctl

go mod download

# Compile all fuzz tests
for fuzz in ShellQuote PowerShellQuote SanitizeBasename RemoteBaseName ParseArg NormalizeWindowsPath AllInstanceIDs NameTag TargetInfoFromInstance FirstInstance NoInstancesFound ListInstancesFiltering DownloadBase64Decoding ParseRemoteFlag ParseS3URL; do
  compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm "Fuzz${fuzz}" fuzz_
done
