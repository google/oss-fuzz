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
# The C codecs (UnRAR, zstd, liblzma, libdeflate, bzip2, lz4) are built from
# vendored sources by their -sys crates, so no apt packages are needed.
# The workspace needs rustc >= 1.95, newer than the base image's nightly.
ENV RUSTUP_TOOLCHAIN=nightly-2026-11-19
RUN rustup toolchain install $RUSTUP_TOOLCHAIN --no-self-update --profile minimal --component rust-src
RUN git clone --depth 1 https://github.com/swseokx/NextZip.git nextzip
WORKDIR $SRC/nextzip
COPY build.sh $SRC/
