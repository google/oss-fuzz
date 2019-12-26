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

# TODO(https://github.com/google/oss-fuzz/issues/3093): Stop specifying the
# image SHA once the bug is fixed.
FROM gcr.io/oss-fuzz-base/base-builder@sha256:276813aef0ce5972db43c0230f96162003994fa742fb1b2f4e66c67498575c65
MAINTAINER htuch@google.com

RUN apt-get update && apt-get -y install  \
	build-essential \
	openjdk-8-jdk   \
	make            \
    ninja-build     \
    curl            \
    autoconf        \
    libtool         \
    wget            \
    golang          \
    python

# Install Bazelisk
RUN wget -O /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/download/v0.0.8/bazelisk-linux-amd64
RUN chmod +x /usr/local/bin/bazel

# Install cmake
RUN wget https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.sh; \
    chmod +x cmake-3.14.5-Linux-x86_64.sh; \
    ./cmake-3.14.5-Linux-x86_64.sh --skip-license --prefix="/usr/local"

RUN git clone https://github.com/envoyproxy/envoy.git
WORKDIR $SRC/envoy/
COPY build.sh $SRC/
