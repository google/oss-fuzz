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

FROM gcr.io/oss-fuzz-base/base-builder-rust:ubuntu-24-04
RUN git clone --depth 1 https://github.com/bus1/dbus-broker

# RUSTUP_TOOLCHAIN is set explicitly to match the latest images
# to get around https://github.com/google/oss-fuzz/issues/14220.
# It should be removed once that issue is resolved.
ENV RUSTUP_TOOLCHAIN nightly-2025-09-05

RUN cargo install bindgen-cli
WORKDIR dbus-broker
COPY *.c build.sh $SRC/
