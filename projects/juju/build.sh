#!/bin/bash -eu
# Copyright 2021 Google LLC
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

go mod download
# A fuzzer in this dependency is broken:
find /root/go/pkg/mod/github.com/aws/aws-sdk-go-v2 -name "*fuzz.go" -exec rm -rf {} \;

# Compile fuzzer:
mv $SRC/storage_fuzzer.go $SRC/juju/storage/
compile_go_fuzzer github.com/juju/juju/storage Fuzz storage_fuzzer
