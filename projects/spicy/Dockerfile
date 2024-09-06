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

FROM gcr.io/oss-fuzz-base/base-builder

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg2 \
    less \
    sudo \
 # Spicy build and test dependencies.
 && apt-get install -y --no-install-recommends \
    git \
    ninja-build \
    bison \
    flex \
    libfl-dev \
    zlib1g-dev \
    libssl-dev \
    locales-all \
 # Spicy doc dependencies.
 && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-sphinx \
    python3-sphinx-rtd-theme \
    python3-setuptools \
    python3-wheel doxygen \
 && pip3 install --no-cache-dir "btest>=0.66" \
 # Install a recent CMake.
 && mkdir -p /opt/cmake \
 && curl -L https://github.com/Kitware/CMake/releases/download/v3.29.2/cmake-3.29.2-linux-x86_64.tar.gz | tar xzvf - -C /opt/cmake --strip-components 1 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/cmake/bin:${PATH}"

RUN git clone --depth 1 --recursive https://github.com/zeek/spicy spicy \
 && git clone --depth 1 --recursive https://github.com/zeek/spicy-dhcp spicy/spicy-dhcp \
 && git clone --depth 1 --recursive https://github.com/zeek/spicy-tftp spicy/spicy-tftp \
 && git clone --depth 1 --recursive https://github.com/zeek/spicy-pe spicy/spicy-pe \
 && git clone --depth 1 --recursive https://github.com/zeek/spicy-png spicy/spicy-png \
 && git clone --depth 1 --recursive https://github.com/zeek/spicy-dns spicy/spicy-dns \
 && git clone --depth 1 --recursive https://github.com/zeek/spicy-http spicy/spicy-http

WORKDIR ${SRC}/spicy

COPY build.sh $SRC/
