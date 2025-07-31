#!/bin/bash -eu
# Copyright 2022 Google LLC
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

# Temporarily disable coverage build in OSS-Fuzz's CI
if [ -n "${OSS_FUZZ_CI-}" ]
then
	if [ "${SANITIZER}" = 'coverage' ]
	then
		exit 0
	fi
	
fi

cd $SRC/go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/

cd $SRC/moby
printf "package libnetwork\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/moby/registerfuzzdependency.go

mv $SRC/moby/vendor.mod $SRC/moby/go.mod
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
find . -type f \( -name "*.go" -o -name "go.mod" \) -exec sed -i 's|github.com/docker/docker|github.com/moby/moby|g' {} +

cp $SRC/jsonmessage_fuzzer.go $SRC/moby/pkg/jsonmessage/
cp $SRC/backend_build_fuzzer.go $SRC/moby/daemon/builder/backend/
cp $SRC/remotecontext_fuzzer.go $SRC/moby/daemon/builder/remotecontext/
cp $SRC/daemon_fuzzer.go $SRC/moby/daemon/

rm -f $SRC/moby/daemon/logger/plugin_unsupported.go

go mod tidy && go mod vendor

mv $SRC/moby/daemon/volume/mounts/parser_test.go $SRC/moby/daemon/volume/mounts/parser_test_fuzz.go
mv $SRC/moby/daemon/volume/mounts/validate_unix_test.go $SRC/moby/daemon/volume/mounts/validate_unix_test_fuzz.go


if [ "$SANITIZER" != "coverage" ] ; then
	go-fuzz -func FuzzDaemonSimple -o FuzzDaemonSimple.a github.com/moby/moby/daemon
	$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzDaemonSimple.a \
        /src/LVM2.2.03.15/libdm/ioctl/libdevmapper.a \
        -o $OUT/FuzzDaemonSimple
fi

go-fuzz -func FuzzDisplayJSONMessagesStream -o FuzzDisplayJSONMessagesStream.a github.com/moby/moby/pkg/jsonmessage
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzDisplayJSONMessagesStream.a -o $OUT/FuzzDisplayJSONMessagesStream
go-fuzz -func FuzzsanitizeRepoAndTags -o FuzzsanitizeRepoAndTags.a github.com/moby/moby/daemon/builder/backend
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzsanitizeRepoAndTags.a -o $OUT/FuzzsanitizeRepoAndTags
go-fuzz -func FuzzreadAndParseDockerfile -o FuzzreadAndParseDockerfile.a github.com/moby/moby/daemon/builder/remotecontext
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzreadAndParseDockerfile.a -o $OUT/FuzzreadAndParseDockerfile

compile_native_go_fuzzer github.com/moby/moby/daemon/volume/mounts FuzzParseLinux FuzzParseLinux
compile_native_go_fuzzer github.com/moby/moby/pkg/tailfile FuzzTailfile FuzzTailfile
compile_native_go_fuzzer github.com/moby/moby/daemon/logger/jsonfilelog FuzzLoggerDecode FuzzLoggerDecode
compile_native_go_fuzzer github.com/moby/moby/daemon/libnetwork/etchosts FuzzAdd FuzzAdd
compile_native_go_fuzzer github.com/moby/moby/daemon/pkg/oci FuzzAppendDevicePermissionsFromCgroupRules FuzzAppendDevicePermissionsFromCgroupRules
compile_native_go_fuzzer github.com/moby/moby/daemon/logger/jsonfilelog/jsonlog FuzzJSONLogsMarshalJSONBuf FuzzJSONLogsMarshalJSONBuf


cp $SRC/*.options $OUT/

cd $SRC/go-archive
printf "package archive\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/go-archive/registerfuzzdependency.go
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer github.com/moby/go-archive/compression FuzzDecompressStream FuzzDecompressStream
compile_native_go_fuzzer github.com/moby/go-archive FuzzApplyLayer FuzzApplyLayer
compile_native_go_fuzzer github.com/moby/go-archive FuzzUntar FuzzUntar
