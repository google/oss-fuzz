# Copyright 2024 Google LLC
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

RUN apt-get update && apt upgrade -y \
  && apt install -y build-essential clang ninja-build

# install llvm
ARG LLVM_VER=15.0.6
RUN cd /opt \
  && wget --progress=dot:giga https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VER}/clang+llvm-${LLVM_VER}-x86_64-linux-gnu-ubuntu-18.04.tar.xz
RUN cd /opt \
  && tar -xvf clang+llvm-${LLVM_VER}-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
  && mv clang+llvm-${LLVM_VER}-x86_64-linux-gnu-ubuntu-18.04 llvm-${LLVM_VER} \
  && rm clang+llvm-${LLVM_VER}-x86_64-linux-gnu-ubuntu-18.04.tar.xz

# install wasm-tools
ARG WASM_TOOLS_VER=1.205.0
RUN cd /opt \
  && wget --progress=dot:giga https://github.com/bytecodealliance/wasm-tools/releases/download/v${WASM_TOOLS_VER}/wasm-tools-${WASM_TOOLS_VER}-x86_64-linux.tar.gz
RUN cd /opt \
  && tar -xvf wasm-tools-${WASM_TOOLS_VER}-x86_64-linux.tar.gz \
  && mv wasm-tools-${WASM_TOOLS_VER}-x86_64-linux wasm-tools \
  && rm wasm-tools-${WASM_TOOLS_VER}-x86_64-linux.tar.gz \
  && ln -s /opt/wasm-tools/wasm-tools /usr/local/bin/wasm-tools

RUN git clone --depth 1 https://github.com/bytecodealliance/wasm-micro-runtime wamr
WORKDIR wamr

COPY build.sh $SRC/
