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
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 --single-branch --branch arbitrary-fuzz https://github.com/juntyr/ron ron
# RUN rustup install nightly-2023-03-24
# RUN rustup component add rust-src --toolchain nightly-2023-03-24-x86_64-unknown-linux-gnu
# RUN rustup default nightly-2023-03-24
WORKDIR ron
COPY build.sh $SRC/
