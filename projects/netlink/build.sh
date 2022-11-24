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

cp $SRC/route_linux_fuzzer.go $SRC/netlink
go mod tidy
go get github.com/AdamKorcz/go-118-fuzz-build/testing
go get golang.org/x/sys
go get github.com/vishvananda/netns

if [ -n "${OSS_FUZZ_CI-}" ]
then
	echo "temporarily not running fuzzer in OSS-Fuzz CI"
else
	compile_native_go_fuzzer github.com/vishvananda/netlink FuzzDeserializeRoute FuzzDeserializeRoute
fi

compile_native_go_fuzzer github.com/vishvananda/netlink FuzzParseRawData FuzzParseRawData
