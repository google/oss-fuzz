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
FROM gcr.io/oss-fuzz-base/base-builder

RUN git clone --depth 1 https://github.com/hyperium/hyper

# TODO move to base-image
RUN cargo install honggfuzz
RUN cargo install afl
RUN apt update && apt install -y build-essential binutils-dev libunwind-dev libblocksruntime-dev liblzma-dev
RUN git clone --branch buildfuzz --depth 1 https://github.com/catenacyber/targets.git hyper/fuzz

COPY build.sh $SRC/

COPY Cargo.toml $SRC/hyper/fuzz/targets/
COPY fuzz*.rs $SRC/
RUN mkdir -p $SRC/hyper/fuzz/targets/src
RUN cd $SRC/hyper/fuzz && ln -s fuzzer-libfuzzer fuzz
RUN cat $SRC/fuzz*.rs > $SRC/hyper/fuzz/targets/src/lib.rs

WORKDIR $SRC/hyper
