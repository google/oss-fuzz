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

COPY build.sh $SRC/

# formatjs is a Bazel + pnpm monorepo. Rather than reproduce that toolchain
# we set up a small fuzz workspace and install the published @formatjs/*
# packages from npm — these are the artifacts downstream users actually run.
RUN mkdir -p $SRC/formatjs

COPY package.json babel.config.json $SRC/formatjs/
COPY fuzz_icu_messageformat_parser.js \
     fuzz_intl_messageformat.js \
     fuzz_icu_skeleton_parser.js \
     $SRC/formatjs/

WORKDIR $SRC/formatjs
