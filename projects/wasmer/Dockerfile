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

FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && apt-get install -y make autoconf automake libtool \
   zlib1g-dev libffi-dev build-essential libxml2-dev

# until clang 16 is used for C cf https://github.com/rust-lang/rust/issues/107149#issuecomment-1492637779
RUN rustup install nightly-2023-03-24
RUN rustup component add rust-src --toolchain nightly-2023-03-24-x86_64-unknown-linux-gnu

RUN git clone --depth 1 https://github.com/wasmerio/wasmer wasmer

RUN mkdir -p $SRC/.llvm && curl --proto '=https' --tlsv1.2 -sSf \
    https://github.com/wasmerio/llvm-custom-builds/releases/download/14.x/llvm-linux-amd64.tar.xz -L -o - | \
    tar xJv -C $SRC/.llvm

WORKDIR wasmer

COPY build.sh default.options $SRC/
