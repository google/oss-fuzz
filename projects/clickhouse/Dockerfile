# Copyright 2021 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update -y \
    && env DEBIAN_FRONTEND=noninteractive \
        apt-get install --yes --no-install-recommends \
            bash \
            wget \
            curl \
            ccache \
            expect \
            ninja-build \
            perl \
            pkg-config \
            python3 \
            python3-lxml \
            python3-requests \
            python3-termcolor \
            protobuf-compiler \
            libprotoc-dev \
            libgrpc++-dev \
            protobuf-compiler-grpc \
            libprotobuf-dev \
            sudo \
            tzdata \
            nasm

# Clone the full source tree before installing its pinned Rust toolchain.
RUN git clone -j 8 --recursive https://github.com/ClickHouse/ClickHouse $SRC/ClickHouse
WORKDIR $SRC/ClickHouse

ENV CARGO_HOME=/rust
ENV RUSTUP_HOME=/rust/rustup
ENV PATH=$PATH:/rust/bin

RUN curl -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y --no-modify-path --default-toolchain none \
    && rm /tmp/rustup-init.sh

# Follow ClickHouse's pin rather than maintaining a second toolchain version.
# Sanitized Rust builds rebuild the standard library and require rust-src.
RUN RUST_TOOLCHAIN="$(sed -n 's/^set(Rust_TOOLCHAIN "\([^"]*\)")$/\1/p' $SRC/ClickHouse/contrib/corrosion-cmake/CMakeLists.txt)" \
    && test -n "$RUST_TOOLCHAIN" \
    && rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal --component rust-src \
    && rustup default "$RUST_TOOLCHAIN"

# HDFS requires Yasm. Keep this build dependency after the expensive source
# checkout so dependency updates can reuse that image layer.
RUN apt-get update -y \
    && apt-get install --yes --no-install-recommends yasm

COPY build.sh $SRC/
