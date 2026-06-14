#!/bin/bash -eu

cd $GOPATH/src/ssmctl

go mod download

# Compile all fuzz tests
for fuzz in ShellQuote PowerShellQuote SanitizeBasename RemoteBaseName ParseArg NormalizeWindowsPath AllInstanceIDs NameTag TargetInfoFromInstance FirstInstance NoInstancesFound ListInstancesFiltering DownloadBase64Decoding ParseRemoteFlag; do
  compile_native_go_fuzzer github.com/rhysmcneill/ssmctl/internal/ssm "Fuzz${fuzz}" fuzz_
done
