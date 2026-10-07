# Copyright 2023 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-javascript

COPY build.sh $SRC/

# For real projects, you would clone your repo in the next step.
RUN mkdir -p $SRC/example

# Ideally, you have already configured fuzz tests in your repo so that they
# run (in Jazzer.js regression mode) as part of unit testing. Keeping the fuzz
# tests in sync with the source code ensures that they are adjusted continue
# to work after code changes. Here, we copy them into the example project directory.
COPY fuzz_string_compare.js fuzz_promise.js fuzz_value_profiling.js package.json $SRC/example/

WORKDIR $SRC/example
