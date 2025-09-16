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

cp $SRC/jsonmessage_fuzzer.go $SRC/moby/client/pkg/jsonmessage/
cp $SRC/backend_build_fuzzer.go $SRC/moby/daemon/builder/backend/
cp $SRC/remotecontext_fuzzer.go $SRC/moby/daemon/builder/remotecontext/
cp $SRC/daemon_fuzzer.go $SRC/moby/daemon/

rm $SRC/moby/daemon/logger/plugin_unsupported.go

cd $SRC/moby
go mod tidy

mv $SRC/moby/daemon/volume/mounts/parser_test.go $SRC/moby/daemon/volume/mounts/parser_test_fuzz.go
mv $SRC/moby/daemon/volume/mounts/validate_unix_test.go $SRC/moby/daemon/volume/mounts/validate_unix_test_fuzz.go


if [ "$SANITIZER" != "coverage" ] ; then
	go-fuzz -func FuzzDaemonSimple -o FuzzDaemonSimple.a github.com/moby/moby/v2/daemon

	$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzDaemonSimple.a \
        /src/LVM2.2.03.15/libdm/ioctl/libdevmapper.a \
        -o $OUT/FuzzDaemonSimple
fi

rm daemon/volume/mounts/validate_windows_test.go
compile_native_go_fuzzer_v2 github.com/moby/moby/v2/daemon/volume/mounts FuzzParseLinux FuzzParseLinux
#compile_go_fuzzer github.com/moby/moby/client/pkg/jsonmessage FuzzDisplayJSONMessagesStream FuzzDisplayJSONMessagesStream
compile_go_fuzzer github.com/moby/moby/v2/daemon/builder/backend FuzzsanitizeRepoAndTags FuzzsanitizeRepoAndTags
compile_go_fuzzer github.com/moby/moby/v2/daemon/builder/remotecontext FuzzreadAndParseDockerfile FuzzreadAndParseDockerfile
compile_native_go_fuzzer_v2 github.com/moby/moby/v2/pkg/tailfile FuzzTailfile FuzzTailfile
compile_native_go_fuzzer_v2 github.com/moby/moby/v2/daemon/logger/jsonfilelog FuzzLoggerDecode FuzzLoggerDecode
compile_native_go_fuzzer_v2 github.com/moby/moby/v2/daemon/libnetwork/etchosts FuzzAdd FuzzAdd
compile_native_go_fuzzer_v2 github.com/moby/moby/v2/daemon/pkg/oci FuzzAppendDevicePermissionsFromCgroupRules FuzzAppendDevicePermissionsFromCgroupRules
compile_native_go_fuzzer_v2 github.com/moby/moby/v2/daemon/logger/jsonfilelog/jsonlog FuzzJSONLogsMarshalJSONBuf FuzzJSONLogsMarshalJSONBuf

cp $SRC/*.options $OUT/

cd $SRC/go-archive
compile_native_go_fuzzer github.com/moby/go-archive/compression FuzzDecompressStream FuzzDecompressStream
compile_native_go_fuzzer github.com/moby/go-archive FuzzApplyLayer FuzzApplyLayer
compile_native_go_fuzzer github.com/moby/go-archive FuzzUntar FuzzUntar
