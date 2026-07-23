# Copyright 2026 Google LLC
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
RUN apt-get update && \
    apt-get -y install \
    git build-essential pkg-config autoconf automake libtool bison flex sed perl libpq-dev curl
RUN git clone --depth 1 https://github.com/stellar/stellar-core stellar-core
WORKDIR $SRC/stellar-core
RUN rm /usr/local/bin/cargo
RUN ./install-rust.sh
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup toolchain install nightly --component rustc,rust-std,rust-src,cargo,clippy,llvm-tools
COPY build.sh $SRC/
