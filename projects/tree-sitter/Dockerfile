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

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    make \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/tree-sitter/tree-sitter $SRC/tree-sitter
RUN git clone --depth 1 https://github.com/tree-sitter/tree-sitter-json $SRC/tree-sitter-json
RUN git clone --depth 1 https://github.com/tree-sitter/tree-sitter-html $SRC/tree-sitter-html
RUN git clone --depth 1 https://github.com/tree-sitter/tree-sitter-javascript $SRC/tree-sitter-javascript

COPY build.sh \
     fuzz_ts_parser.c \
     fuzz_ts_query.c \
     fuzz_ts_subtree.c \
     fuzz_ts_parser.dict \
     fuzz_ts_query.dict \
     fuzz_ts_subtree.dict \
     $SRC/

WORKDIR $SRC/tree-sitter
