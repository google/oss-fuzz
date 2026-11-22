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

# Ubuntu 24.04's git (2.43) fetches with protocol v2: GitHub refuses the
# shallow protocol v0 fetch that 20.04's git 2.25 makes.
FROM gcr.io/oss-fuzz-base/base-builder-rust:ubuntu-24-04
# The base image's nightly predates fuzz/Cargo.toml's rust-version, and too
# old to build cargo-fuzz, it ships without it.
ENV RUSTUP_TOOLCHAIN=nightly-2026-01-20
RUN rustup toolchain install $RUSTUP_TOOLCHAIN --profile minimal --component rust-src \
    && cargo install cargo-fuzz --locked && rm -rf /rust/registry
# jq, zip, and xxd for the seed corpora; aws-lc-sys, the differential oracle, builds C.
RUN apt-get update && apt-get install -y --no-install-recommends jq zip cmake xxd
RUN git clone --depth 1 https://github.com/kixel-ai/rind
WORKDIR $SRC/rind
COPY build.sh $SRC/
