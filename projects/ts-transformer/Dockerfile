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

# base-builder-rust ships a pinned nightly toolchain (via RUSTUP_TOOLCHAIN)
# plus cargo-fuzz. We add cmake (vendored libsrt + mbedTLS build), pkg-config
# (the srt-sys build script probes it before falling back to the vendored
# tree) and libclang-dev (bindgen in srt-sys).
FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    pkg-config \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Only the two submodules a fuzz build links against: libsrt
# (crates/srt-sys/vendor/srt, pulled in by tst-srt's url_parse harness) and
# mbedTLS (crates/mbedtls-src/vendor/mbedtls, libsrt's crypto backend; its
# nested `framework` submodule is required by its CMake configure, hence
# --recursive). The librist and embedded/ vendor trees are not used by any
# fuzz target.
RUN git clone --depth 1 https://github.com/aklofas/ts-transformer "$SRC/ts-transformer" \
    && git -C "$SRC/ts-transformer" submodule update --init --recursive --depth 1 \
        crates/srt-sys/vendor/srt \
        crates/mbedtls-src/vendor/mbedtls

WORKDIR $SRC/ts-transformer

COPY build.sh $SRC/
