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

ENV CARGO_HOME=/rust
ENV RUSTUP_HOME=/rust/rustup
ENV PATH=$PATH:/rust/bin
# Set up custom environment variable for source code copy for coverage reports
ENV OSSFUZZ_RUSTPATH /rust

# Force rustup to ignore `rust-toolchain` and `rust-toolchain.toml` files by
# manually specifying what toolchain to use. Note that this environment variable
# is additionally used by `install_rust.sh` as the toolchain to install.
# cf https://rust-lang.github.io/rustup/overrides.html
ENV RUSTUP_TOOLCHAIN nightly-2024-07-12

# Configure the linker used by default for x86_64 linux to be `clang` instead of
# rustc's default of `cc` which is able to find custom-built libraries like
# `libc++` by default more easily.
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER clang

RUN install_rust.sh
