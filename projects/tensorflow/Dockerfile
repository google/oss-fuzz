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

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        rsync \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install numpy

# Due to Bazel bug, need to symlink python3 to python
# See https://github.com/bazelbuild/bazel/issues/8665
RUN ln -s /usr/local/bin/python3 /usr/local/bin/python

# Install Bazelisk to keep bazel in sync with the version required by TensorFlow
RUN curl -Lo /usr/bin/bazel \
        https://github.com/bazelbuild/bazelisk/releases/download/v1.1.0/bazelisk-linux-amd64 \
        && \
    chmod +x /usr/bin/bazel

ENV JAVA_HOME /usr/lib/jvm/java-15-openjdk-amd64
# it fails after installing java due to jazzer env variables missing
RUN install_java.sh || true

RUN git clone --depth 1 https://github.com/tensorflow/tensorflow tensorflow
WORKDIR $SRC/tensorflow
COPY build.sh $SRC/
COPY *.patch $SRC/
