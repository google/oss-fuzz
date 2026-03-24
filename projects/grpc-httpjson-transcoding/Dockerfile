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

# Todo: unpin to support llvm 22
FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04@sha256:d34b94e3cf868e49d2928c76ddba41fd4154907a1a381b3a263fafffb7c3dce0
MAINTAINER nareddyt@google.com

RUN apt-get update && apt-get install python3 -y
RUN git clone https://github.com/grpc-ecosystem/grpc-httpjson-transcoding.git
WORKDIR $SRC/grpc-httpjson-transcoding/
COPY build.sh $SRC/
