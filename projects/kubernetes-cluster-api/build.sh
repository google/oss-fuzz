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

cp $SRC/cncf-fuzzing/projects/cluster-api/yaml_fuzzer.go \
	$SRC/cluster-api/util/yaml/

compile_go_fuzzer sigs.k8s.io/cluster-api/util/yaml FuzzYamlParse fuzz_yaml_parser
