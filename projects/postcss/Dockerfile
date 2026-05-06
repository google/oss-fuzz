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

# PostCSS's default branch is `main`. Pin it explicitly so the integration
# does not silently break if the default ever changes.
RUN git clone --depth 1 -b main https://github.com/postcss/postcss

# postcss-parser-tests is the upstream-maintained collection of CSS test
# cases. We use its `cases/` directory as the seed corpus so the fuzzer
# starts mutating from real, parser-shaped inputs.
RUN git clone --depth 1 -b main https://github.com/postcss/postcss-parser-tests

COPY fuzz_parse.js fuzz_parse.dict $SRC/postcss/

WORKDIR $SRC/postcss
