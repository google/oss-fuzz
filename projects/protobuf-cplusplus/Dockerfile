# Copyright 2022 Google Inc.
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

# RUN apt-get update && apt-get install -y cmake

RUN git clone --depth 1 --recursive https://github.com/protocolbuffers/protobuf.git

COPY WORKSPACE .bazelrc BUILD $SRC/
RUN cat WORKSPACE >> $SRC/protobuf/WORKSPACE
RUN cat .bazelrc >> $SRC/protobuf/.bazelrc
RUN cat BUILD >> $SRC/protobuf/src/google/protobuf/BUILD.bazel

RUN mkdir $SRC/protobuf/src/google/protobuf/fuzz
COPY fuzz*.cc $SRC/protobuf/src/google/protobuf/fuzz/

WORKDIR $SRC/protobuf
COPY build.sh $SRC/
