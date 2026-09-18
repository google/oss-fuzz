# Copyright 2026 Google LLC
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

# Clone the upstream repository so OSS-Fuzz tracks the source.
RUN git clone --depth 1 https://github.com/rollup/rollup.git

# Set up a separate workspace where Rollup is installed from npm
# (the published package ships prebuilt native bindings, avoiding a Rust/WASM
# toolchain inside the fuzz image).
RUN mkdir -p $SRC/rollup-fuzz

COPY build.sh $SRC/
COPY package.json $SRC/rollup-fuzz/
COPY fuzz_parse_ast.js $SRC/rollup-fuzz/
COPY fuzz_log_filter.js $SRC/rollup-fuzz/
COPY fuzz_bundle.js $SRC/rollup-fuzz/

WORKDIR $SRC/rollup-fuzz
