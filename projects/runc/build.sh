#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

#apt-get install curl
mv $SRC/id_map_fuzzer.go $SRC/runc/libcontainer/system/
compile_go_fuzzer ./libcontainer/system Fuzz id_map_fuzzer linux

mv $SRC/user_fuzzer.go $SRC/runc/libcontainer/user
compile_go_fuzzer ./libcontainer/user Fuzz user_fuzzer

mv $SRC/configs_fuzzer.go $SRC/runc/libcontainer/configs
compile_go_fuzzer ./libcontainer/configs Fuzz configs_fuzzer



# Integration tests trying: 
mkdir $SRC/runc/libcontainer/integration/fuzzing
mv $SRC/fuzz.go $SRC/runc/libcontainer/integration/fuzzing/
#mv $SRC/fuzz_utils.go $SRC/runc/libcontainer/integration/
mv $SRC/runc/libcontainer/integration/utils_test.go \
	$SRC/runc/libcontainer/integration/fuzz_utils.go

mv $SRC/runc/libcontainer/integration/template_test.go \
	$SRC/runc/libcontainer/integration/template_fuzz_utils.go

mv $SRC/runc/libcontainer/integration/init_test.go \
	$SRC/runc/libcontainer/integration/fuzz_init.go


compile_go_fuzzer ./libcontainer/integration/fuzzing Fuzz fuzz
