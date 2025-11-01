#!/bin/bash
# Copyright 2024 Google LLC
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
PROJECT=$1
FUZZING_LANGUAGE=$2

gcloud builds submit "https://github.com/google/oss-fuzz" \
  --async \
  --git-source-revision=master \
  --config=cloudbuild.yaml \
  --substitutions=_PROJECT=$PROJECT,_FUZZING_LANGUAGE=$FUZZING_LANGUAGE \
  --project=oss-fuzz \
  --region=us-central1
