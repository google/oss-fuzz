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

FROM gcr.io/oss-fuzz-base/base-builder:latest

# Install prerequisite packages
# See connectedhomeip/docs/guides/BUILDING.md#prerequisites
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev libdbus-1-dev libglib2.0-dev \
        libavahi-client-dev ninja-build \
        unzip libgirepository1.0-dev libcairo2-dev libreadline-dev

RUN pip3 install meson


RUN cd /tmp && \
    wget https://download.gnome.org/sources/glib/2.68/glib-2.68.0.tar.xz && \
    tar xf glib-2.68.0.tar.xz && \
    cd glib-2.68.0 && \
    meson _build --prefix=/usr/local \
        --default-library=both && \
    ninja -C _build && \
    ninja -C _build install && \
    ldconfig && \
    cd / && rm -rf /tmp/glib-2.68.0*


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