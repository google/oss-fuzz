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
# fallow needs Rust 1.96 or later. The nightly of the base image is older, so
# install the nightly that the fallow fuzz CI job uses.
ENV RUSTUP_TOOLCHAIN=nightly-2026-07-20
RUN rustup toolchain install $RUSTUP_TOOLCHAIN --profile minimal --component rust-src
RUN git clone --depth 1 https://github.com/fallow-rs/fallow fallow
WORKDIR $SRC/fallow
COPY build.sh $SRC/
