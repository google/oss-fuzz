#!/bin/bash -eux
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

# Install dependencies in a platform-aware way.
apt-get update && apt-get install -y \
    binutils \
    curl \
    file \
    fonts-dejavu \
    git \
    libcap2 \
    rsync \
    unzip \
    wget \
    zip --no-install-recommends

# Install Python3.10 as this is needed to extract code coverage for Python
# projects that require 3.10+ syntax.
apt-get update -y \
    && apt-get install -y libgdal26 software-properties-common \
    && add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get install -y python3.10 python3.10-dev \
    && ln --force -s /usr/bin/python3.10 /usr/local/bin/python3 \
    && curl -sS https://bootstrap.pypa.io/get-pip.py | python3

case $(uname -m) in
  x86_64)
    # We only need to worry about i386 if we are on x86_64.
    apt-get install -y lib32gcc1 libc6-i386
    ;;
esac
