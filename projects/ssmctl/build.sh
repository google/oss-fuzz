#!/bin/bash -eu
# MIT License
#
# Copyright (c) 2026 rhysmcneill
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#################################################################################
cd $GOPATH/src/github.com/MozamilS/ssmctl/

go mod download
go mod tidy

echo "=== FUZZ FUNCTIONS FOUND ==="
grep -r "^func Fuzz" $GOPATH/src/github.com/MozamilS/ssmctl/internal/ssm/
echo "=== END FUZZ FUNCTIONS ==="

compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzSanitizeBasename fuzz_sanitizebasename
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzRemoteBaseName fuzz_remotebasename
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzDownloadBase64Decoding fuzz_downloadbase64decoding
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzAllInstanceIDs fuzz_allinstanceids
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzFirstInstance fuzz_firstinstance
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzShellQuote fuzz_shellquote
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzPowerShellQuote fuzz_powershellquote
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzNoInstancesFound fuzz_noinstancesfound
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzNormalizeWindowsPath fuzz_normalizewindowspath
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzTargetInfoFromInstance fuzz_targetinfofrommodule
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzParseRemoteFlag fuzz_parseremotsflag
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzNameTag fuzz_nametag
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzParseArg fuzz_parsearg
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzParseS3URL fuzz_parses3url
compile_native_go_fuzzer github.com/MozamilS/ssmctl/internal/ssm FuzzListInstancesFiltering fuzz_list
