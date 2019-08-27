# Copyright 2018 Google Inc.
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
MAINTAINER mihaimaruseac@google.com

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        python-dev \
        python-future \
        rsync \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Bazel from apt-get to ensure dependencies are there
RUN echo "deb [arch=amd64] http://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list
RUN curl https://bazel.build/bazel-release.pub.gpg | apt-key add -
RUN apt-get update && apt-get install -y bazel

RUN git clone --depth 1 https://github.com/tensorflow/tensorflow tensorflow
WORKDIR $SRC/tensorflow
COPY build.sh $SRC/
