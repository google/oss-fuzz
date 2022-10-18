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
# Build Stage
FROM ubuntu:20.04 as builder

## Install build dependencies.
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git-all cmake clang curl binutils-dev libunwind8-dev
RUN curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN ${HOME}/.cargo/bin/rustup default nightly
RUN ${HOME}/.cargo/bin/cargo install honggfuzz --version 0.5.55

## Add source code to the build stage.
RUN git clone https://github.com/paritytech/polkadot.git
WORKDIR /polkadot
RUN cd xcm/xcm-simulator/fuzzer && \
	${HOME}/.cargo/bin/cargo hfuzz build
RUN cd erasure-coding/fuzzer && \
	${HOME}/.cargo/bin/cargo hfuzz build
#package stage 
FROM gcr.io/oss-fuzz-base/base-builder-rust

## Install build dependencies.
RUN apt-get update
RUN apt-get install -y cmake clang curl binutils-dev libunwind8-dev libblocksruntime-dev
COPY build.sh $SRC/
COPY --from=builder /polkadot/xcm/xcm-simulator/fuzzer/hfuzz_target/x86_64-unknown-linux-gnu/release/xcm-fuzzer $OUT/
COPY --from=builder /polkadot/erasure-coding/fuzzer/hfuzz_target/x86_64-unknown-linux-gnu/release/xcm-fuzzer $OUT/
COPY --from=builder /polkadot/erasure-coding/fuzzer/hfuzz_target/x86_64-unknown-linux-gnu/release/xcm-fuzzer $OUT/