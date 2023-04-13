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

cd $SRC/instrumentation
go run main.go --target_dir=$SRC/moby --check_io_length=true
cd $SRC/moby
printf "package libnetwork\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/moby/registerfuzzdependency.go

mv $SRC/moby/vendor.mod $SRC/moby/go.mod

cp $SRC/jsonmessage_fuzzer.go $SRC/moby/pkg/jsonmessage/
cp $SRC/backend_build_fuzzer.go $SRC/moby/api/server/backend/build/
cp $SRC/remotecontext_fuzzer.go $SRC/moby/builder/remotecontext/
cp $SRC/containerstream_fuzzer.go $SRC/moby/container/stream/
cp $SRC/daemon_fuzzer.go $SRC/moby/daemon/

rm $SRC/moby/pkg/archive/example_changes.go
rm $SRC/moby/daemon/logger/plugin_unsupported.go

cd $SRC/moby
go mod tidy && go mod vendor

mv $SRC/moby/volume/mounts/parser_test.go $SRC/moby/volume/mounts/parser_test_fuzz.go
mv $SRC/moby/volume/mounts/validate_unix_test.go $SRC/moby/volume/mounts/validate_unix_test_fuzz.go


if [ "$SANITIZER" != "coverage" ] ; then
	go-fuzz -func FuzzDaemonSimple -o FuzzDaemonSimple.a github.com/docker/docker/daemon

	$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzDaemonSimple.a \
        /src/LVM2.2.03.15/libdm/ioctl/libdevmapper.a \
        -o $OUT/FuzzDaemonSimple
fi

compile_native_go_fuzzer github.com/docker/docker/volume/mounts FuzzParseLinux FuzzParseLinux
compile_go_fuzzer github.com/docker/docker/pkg/jsonmessage FuzzDisplayJSONMessagesStream FuzzDisplayJSONMessagesStream
compile_go_fuzzer github.com/docker/docker/api/server/backend/build FuzzsanitizeRepoAndTags FuzzsanitizeRepoAndTags
compile_go_fuzzer github.com/docker/docker/builder/remotecontext FuzzreadAndParseDockerfile FuzzreadAndParseDockerfile
compile_go_fuzzer github.com/docker/docker/container/stream FuzzcopyEscapable FuzzcopyEscapable
compile_native_go_fuzzer github.com/docker/docker/pkg/archive FuzzUntar FuzzUntar
compile_native_go_fuzzer github.com/docker/docker/pkg/archive FuzzDecompressStream FuzzDecompressStream
compile_native_go_fuzzer github.com/docker/docker/pkg/archive FuzzApplyLayer FuzzApplyLayer
compile_native_go_fuzzer github.com/docker/docker/pkg/tailfile FuzzTailfile FuzzTailfile
compile_native_go_fuzzer github.com/docker/docker/daemon/logger/jsonfilelog FuzzLoggerDecode FuzzLoggerDecode
compile_native_go_fuzzer github.com/docker/docker/libnetwork/etchosts FuzzAdd FuzzAdd
compile_native_go_fuzzer github.com/docker/docker/oci FuzzAppendDevicePermissionsFromCgroupRules FuzzAppendDevicePermissionsFromCgroupRules
compile_native_go_fuzzer github.com/docker/docker/daemon/logger/jsonfilelog/jsonlog FuzzJSONLogsMarshalJSONBuf FuzzJSONLogsMarshalJSONBuf

cp $SRC/*.options $OUT/
