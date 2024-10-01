#!/bin/bash
# Copyright 2024 Google Inc.
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

# Build all C/C++ projects.
c_project_yaml=$(find projects/ -name project.yaml -exec grep -l 'language: c' {} \;)
projs=$(echo $c_project_yaml | xargs dirname | xargs basename -a | sort)

for proj in $projs; do
    fuzz_target=$(curl -s "https://introspector.oss-fuzz.com/api/harness-source-and-executable?project=$proj" | jq --raw-output '.pairs[0].executable')
    if [ "$fuzz_target" != null ]; then
        echo ./build_on_cloudbuild.sh $proj $fuzz_target c
    fi
done