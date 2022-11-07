# Copyright 2022 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:c4a0d90b29bd1f988d000eeb4d704b1de2e58708b1f33b653a91a5bb4d913c05
RUN curl -L -O https://raw.githubusercontent.com/protobuf-c/protobuf-c/39cd58f5ff06048574ed5ce17ee602dc84006162/t/test-full.proto
RUN git clone https://github.com/protocolbuffers/protobuf.git
RUN cd protobuf && bazel build --nobuild //:protoc @upb//python/dist:binary_wheel
COPY build.sh fuzz_* $SRC/
