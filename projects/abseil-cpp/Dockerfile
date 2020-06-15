# Copyright 2020 Google Inc.
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
RUN apt-get update && apt-get --no-install-recommends install -y build-essential make curl wget rsync

RUN echo "deb [arch=amd64] http://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list
RUN curl https://bazel.build/bazel-release.pub.gpg | apt-key add -
RUN apt-get update && apt-get install -y bazel
RUN curl -Lo /usr/bin/bazel \
        https://github.com/bazelbuild/bazelisk/releases/download/v1.1.0/bazelisk-linux-amd64 \
        && \
    chmod +x /usr/bin/bazel

RUN git clone --depth 1 https://github.com/abseil/abseil-cpp.git

COPY BUILD WORKSPACE build.sh string_escape_fuzzer.cc string_utilities_fuzzer.cc $SRC/