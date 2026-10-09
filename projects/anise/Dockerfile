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
RUN git clone --depth 1 --branch master https://github.com/nyx-space/anise anise
RUN apt-get update && apt-get install -y tcsh libc++-dev libc++abi-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    cd anise && ./dev-env-setup.sh
ENV RUSTUP_TOOLCHAIN=nightly-2025-07-03
ENV RUSTFLAGS="-C link-arg=-lc++"
WORKDIR $SRC
COPY build.sh $SRC/
