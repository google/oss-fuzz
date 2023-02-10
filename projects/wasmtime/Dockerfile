# Copyright 2020 Google Inc.
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
RUN apt-get update && apt-get install -y make autoconf automake libtool curl \
  cmake python llvm-dev libclang-dev clang \
  libgmp-dev

# Install a newer version of OCaml than provided by Ubuntu 16.04 (base version for this image)
RUN curl -sL https://raw.githubusercontent.com/ocaml/opam/master/shell/install.sh -o install.sh && \
  echo | sh install.sh && \
  opam init --disable-sandboxing --yes --compiler=4.11.2 && \
  opam install ocamlbuild ocamlfind --yes && \
  CFLAGS= opam install zarith --yes

RUN git clone --depth 1 https://github.com/bytecodealliance/wasm-tools wasm-tools

RUN git clone --depth 1 https://github.com/bytecodealliance/regalloc2 regalloc2

RUN git clone --depth 1 https://github.com/bytecodealliance/wasmtime wasmtime
WORKDIR wasmtime
#RUN git submodule update --init --recursive

#RUN git clone --depth 1 https://github.com/bytecodealliance/wasmtime-libfuzzer-corpus wasmtime-libfuzzer-corpus

COPY build.sh *.options $SRC/
