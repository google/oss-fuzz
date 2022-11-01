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

mv $SRC/moby/vendor.mod $SRC/moby/go.mod

cp $SRC/mounts_fuzzer.go $SRC/moby/volume/mounts/
cp $SRC/tailfile_fuzzer.go $SRC/moby/pkg/tailfile/
cp $SRC/archive_fuzzers.go $SRC/moby/pkg/archive/
cp $SRC/jsonfilelog_fuzzer.go $SRC/moby/daemon/logger/jsonfilelog/
cp $SRC/etchosts_fuzzer.go $SRC/moby/libnetwork/etchosts/

rm $SRC/moby/pkg/archive/example_changes.go
rm $SRC/moby/daemon/logger/plugin_unsupported.go

cd $SRC/moby
go mod tidy && go mod vendor
go get github.com/AdaLogics/go-fuzz-headers@latest
go mod vendor

mv $SRC/moby/volume/mounts/parser_test.go $SRC/moby/volume/mounts/parser_test_fuzz.go
mv $SRC/moby/volume/mounts/validate_unix_test.go $SRC/moby/volume/mounts/validate_unix_test_fuzz.go
compile_go_fuzzer github.com/docker/docker/volume/mounts FuzzParseLinux FuzzParseLinux

compile_go_fuzzer github.com/docker/docker/pkg/archive FuzzUntar FuzzUntar
compile_go_fuzzer github.com/docker/docker/pkg/archive FuzzDecompressStream FuzzDecompressStream
compile_go_fuzzer github.com/docker/docker/pkg/archive FuzzApplyLayer FuzzApplyLayer
compile_go_fuzzer github.com/docker/docker/pkg/tailfile FuzzTailfile FuzzTailfile
compile_go_fuzzer github.com/docker/docker/daemon/logger/jsonfilelog FuzzLoggerDecode FuzzLoggerDecode

compile_go_fuzzer github.com/docker/docker/libnetwork/etchosts FuzzAdd FuzzAdd

cp $SRC/*.options $OUT/