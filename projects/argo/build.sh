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

mv $SRC/normalizer_fuzzer.go $SRC/argo-cd/util/argo/normalizers/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/argo/normalizers FuzzNormalize fuzz_normalize

mv $SRC/workflow_validation_fuzzer.go $SRC/argo-workflows/workflow/validate/
cd $SRC/argo-workflows
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/validate FuzzValidateWorkflow fuzz_validate_workflow
