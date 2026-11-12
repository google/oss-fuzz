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
RUN apt-get update && apt-get install -y autoconf automake libtool
RUN curl -fsSL https://nodejs.org/dist/v26.10.0/node-v26.10.0-linux-x64.tar.xz \
    | tar -xJ --strip-components=1 -C /usr/local
RUN rustup toolchain install nightly --profile minimal --component rust-src
ENV RUSTUP_TOOLCHAIN=nightly
RUN git clone --depth 1 https://github.com/sqlpage/SQLPage.git $SRC/sqlpage
WORKDIR $SRC/sqlpage
RUN npm ci --ignore-scripts && npm run build
COPY build.sh sql_file.dict sql_file.options $SRC/
