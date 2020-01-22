# Copyright 2019 Google Inc.
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

# TODO(https://github.com/google/oss-fuzz/issues/3093): Stop specifying the
# image SHA once the bug is fixed.
FROM gcr.io/oss-fuzz-base/base-builder@sha256:276813aef0ce5972db43c0230f96162003994fa742fb1b2f4e66c67498575c65
MAINTAINER tzn@google.com

# Use a fixed Bazel version.
# https://github.com/google/asylo/blob/088ea3490dd4579655bd5b65b0e31fe18de7f6dd/asylo/distrib/toolchain/Dockerfile#L48-L71
ARG bazel_version=1.1.0
ARG bazel_sha=138b47ffd54924e3c0264c65d31d3927803fb9025db4d5b18107df79ee3bda95
ARG bazel_url=https://storage.googleapis.com/bazel-apt/pool/jdk1.8/b/bazel/bazel_${bazel_version}_amd64.deb

# Install Bazel.
RUN apt-get update && \
    apt-get install -y wget && \
    wget "${bazel_url}" -nv -o- -O bazel.deb && \
    echo "${bazel_sha}  bazel.deb" > bazel.sha256 && \
    sha256sum --check bazel.sha256 && \
    apt-get install -y ./bazel.deb && \
    rm bazel.deb bazel.sha256 && \
    apt-get clean

RUN git clone --depth 1 https://github.com/project-oak/oak oak
WORKDIR oak
COPY build.sh $SRC/
