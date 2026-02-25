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

FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        cmake protobuf-compiler pkg-config python3 libclang-dev \
        libdbus-1-dev lld

ENV RUSTUP_TOOLCHAIN nightly-2025-12-15

RUN rustup install $RUSTUP_TOOLCHAIN
RUN rustup component add rust-src --toolchain $RUSTUP_TOOLCHAIN

RUN git clone --depth 1 https://github.com/denoland/deno $SRC/deno

WORKDIR $SRC/deno

COPY build.sh $SRC/
