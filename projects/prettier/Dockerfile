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

RUN git clone --depth 1 https://github.com/prettier/prettier.git

# Prettier's own package.json sets "type": "module", which makes every .js
# file inside the repo be loaded as ESM. The fuzz targets are written in
# CommonJS, so they live in a subdirectory carrying its own package.json
# with "type": "commonjs" to override the parent setting.
RUN mkdir -p $SRC/prettier/fuzz_targets
COPY fuzz_targets/package.json \
     fuzz_targets/fuzz_format_js.js \
     fuzz_targets/fuzz_format_ts.js \
     fuzz_targets/fuzz_format_css.js \
     fuzz_targets/fuzz_format_json.js \
     fuzz_targets/fuzz_format_md.js \
     $SRC/prettier/fuzz_targets/

WORKDIR $SRC/prettier
