#!/bin/bash -eux
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

curl https://sh.rustup.rs | sh -s -- -y --default-toolchain=nightly --profile=minimal
cargo install cargo-fuzz && rm -rf /rust/registry
# Needed to recompile rust std library for MSAN
rustup component add rust-src --toolchain nightly
