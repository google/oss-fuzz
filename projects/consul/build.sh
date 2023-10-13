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

mv $SRC/agent_fuzzer.go ./agent/
mv $SRC/acl_fuzzer.go ./acl/

compile_go_fuzzer github.com/hashicorp/consul/agent FuzzAddService fuzz_add_service
compile_go_fuzzer github.com/hashicorp/consul/agent FuzzdecodeBody fuzz_decode_body
compile_go_fuzzer github.com/hashicorp/consul/acl FuzzNewPolicyFromSource fuzz_new_policy_from_source
