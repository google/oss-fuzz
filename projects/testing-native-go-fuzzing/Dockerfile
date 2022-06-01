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

FROM gcr.io/oss-fuzz-base/base-builder-go
RUN git clone --depth 1 https://github.com/vitessio/vitess
RUN go install golang.org/dl/gotip@latest \
    && gotip download
RUN go install github.com/AdamKorcz/go-118-fuzz-build@latest
COPY build.sh \
     native_ossfuzz_coverage_runnger.go \
     fuzzers/tablet_manager_fuzzer_test.go \
     fuzzers/parser_fuzzer_test.go \
     fuzzers/ast_fuzzer_test.go \
     $SRC/
WORKDIR $SRC/vitess
