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

# Install prerequisite packages
# See connectedhomeip/docs/guides/BUILDING.md#prerequisites
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev libdbus-1-dev libglib2.0-dev \
        libavahi-client-dev ninja-build \
        unzip libgirepository1.0-dev libcairo2-dev libreadline-dev

# Build Python 3.10 from source (no more available in deadsnakes for Ubuntu 20.04)
# ONCE OSS-Fuzz release Base image with Ubuntu 24.04, we can switch to that and stop building python from source
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential zlib1g-dev libncurses5-dev libgdbm-dev libgdbm-compat-dev \
        libnss3-dev libffi-dev libsqlite3-dev wget curl ca-certificates \
        libbz2-dev liblzma-dev xz-utils uuid-dev && \
    rm -rf /var/lib/apt/lists/* && \
    cd /tmp && set -eux; \
    curl -fL https://www.python.org/ftp/python/3.10.14/Python-3.10.14.tgz -o Python-3.10.14.tgz && \
    tar -xf Python-3.10.14.tgz && \
    cd Python-3.10.14 && \
    ./configure --enable-optimizations --prefix=/usr/local \
                --with-lto --enable-shared && \
    make -j"$(nproc)" && \
    make altinstall && \
    ln --force -s /usr/local/bin/python3.10 /usr/bin/python3 && \
    ln --force -s /usr/local/bin/pip3.10 /usr/bin/pip3 && \
    echo "/usr/local/lib" > /etc/ld.so.conf.d/python3.10.conf && ldconfig && \
    cd / && rm -rf /tmp/Python-3.10.14*


# PEP-517 needed for cryptography. Update pip
RUN python3 -m ensurepip --upgrade && \
    python3 -m pip install --upgrade pip setuptools wheel packaging
    
# Install Rust for building `cryptography` python package when bootstraping pigweed
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup install nightly
RUN rustup default nightly

RUN git clone --depth=1 https://github.com/project-chip/connectedhomeip.git connectedhomeip

# PW_PROJECT_ROOT is used in requirements.build.txt
ENV PW_PROJECT_ROOT=$SRC/connectedhomeip

# Ensure global python has access to build requirements
RUN pip3 install -r connectedhomeip/scripts/setup/requirements.build.txt

# checkout submodules required for linux
RUN cd $SRC/connectedhomeip && scripts/checkout_submodules.py --shallow --platform linux

# Bootstrap pigweed environment
SHELL ["/bin/bash", "-c"]
RUN cd $SRC/connectedhomeip && . scripts/bootstrap.sh

COPY build.sh $SRC/