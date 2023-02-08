# Copyright 2023 Google LLC
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
RUN apt-get update
#RUN git clone --depth 1 https://github.com/magma/magma.git
RUN git clone --depth 1 https://github.com/0x34d/magma.git
COPY build.sh $SRC/
WORKDIR $SRC/magma/


RUN apt-get update && \
  # Setup necessary tools for adding the Magma repository
  apt-get install -y apt-utils software-properties-common apt-transport-https gnupg wget && \
  # Download Bazel
  wget -P /usr/sbin --progress=dot:giga https://github.com/bazelbuild/bazelisk/releases/download/v1.10.0/bazelisk-linux-amd64 && \
  chmod +x /usr/sbin/bazelisk-linux-amd64 && \
  ln -s /usr/sbin/bazelisk-linux-amd64 /usr/sbin/bazel

# Install dependencies required for building
RUN apt-get update && apt-get install -y \
  autoconf \
  autogen \
  build-essential \
  ccache \
  check \
  cmake \
  curl \
  git \
  libboost-chrono-dev \
  libboost-context-dev \
  libboost-program-options-dev \
  libboost-filesystem-dev \
  libboost-regex-dev \
  libc++-dev \
  libconfig-dev \
  libcurl4-openssl-dev \
  libczmq-dev \
  libdouble-conversion-dev \
  libgflags-dev \
  libgmp3-dev \
  libgoogle-glog-dev \
  libmnl-dev \
  libpcap-dev \
  libprotoc-dev \
  libsctp-dev \
  libsqlite3-dev \
  libssl-dev \
  libtspi-dev \
  libtool \
  libxml2-dev \
  libxslt-dev \
  libyaml-cpp-dev \
  ninja-build \
  nlohmann-json3-dev \
  pkg-config \
  protobuf-compiler \
  python3-pip \
  sudo \
  unzip \
  uuid-dev

# Add the magma apt repo
#COPY keys/linux_foundation_registry_key.asc /etc/apt/trusted.gpg.d/magma.asc
RUN cp keys/linux_foundation_registry_key.asc /etc/apt/trusted.gpg.d/magma.asc
RUN echo "deb https://linuxfoundation.jfrog.io/artifactory/magma-packages-test focal-ci main" > /etc/apt/sources.list.d/magma.list
RUN apt-get update && apt-get install -y \
  grpc-dev \
  libfolly-dev \
  liblfds710 \
  magma-cpp-redis \
  magma-libfluid \
  oai-asn1c \
  oai-freediameter \
  oai-gnutls \
  oai-nettle \
  prometheus-cpp-dev
