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

FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get --yes update \
  && apt-get install --no-install-recommends --yes \
  libssl-dev \
  pkg-config \
  python \
  && apt-get clean \
  && rm --recursive --force /var/lib/apt/lists/*

# Install rustup.
ARG rustup_dir=/rust
RUN curl --location https://sh.rustup.rs > /tmp/rustup \
  && sh /tmp/rustup -y --default-toolchain=none \
  && chmod a+rwx ${rustup_dir} \
  && rustup --version

# Install Rust toolchain.
# We currently need the nightly version in order to be able to compile some of the examples.
# See https://rust-lang.github.io/rustup-components-history/ for how to pick a version that supports
# the appropriate set of components.
ARG rust_version=nightly-2023-02-13
RUN rustup toolchain install ${rust_version} \
  && rustup default ${rust_version}

# Install WebAssembly target for Rust.
RUN rustup target add wasm32-unknown-unknown

# Install musl target for Rust (for statically linked binaries).
RUN rustup target add x86_64-unknown-linux-musl

# Install rust-src. Needed to recompile rust std library for MSAN
RUN rustup component add rust-src

# Install Protobuf compiler.
ARG protobuf_version=3.13.0
ARG protobuf_sha256=4a3b26d1ebb9c1d23e933694a6669295f6a39ddc64c3db2adf671f0a6026f82e
ARG protobuf_dir=/usr/local/protobuf
ARG protobuf_temp=/tmp/protobuf.zip
ENV PATH "${protobuf_dir}/bin:${PATH}"
RUN curl --location https://github.com/protocolbuffers/protobuf/releases/download/v${protobuf_version}/protoc-${protobuf_version}-linux-x86_64.zip > ${protobuf_temp} \
  && sha256sum --binary ${protobuf_temp} && echo "${protobuf_sha256} *${protobuf_temp}" | sha256sum --check \
  && unzip ${protobuf_temp} -d ${protobuf_dir} \
  && rm ${protobuf_temp} \
  && chmod --recursive a+rwx ${protobuf_dir} \
  && protoc --version

RUN git clone --depth 1 https://github.com/project-oak/oak oak

WORKDIR oak
COPY build.sh $SRC/
