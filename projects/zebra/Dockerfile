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

# OSS-Fuzz build environment for the Zebra coverage-guided fuzz suite.
#
# base-builder-rust ships the nightly toolchain + cargo-fuzz pre-installed
# (https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/).
FROM gcr.io/oss-fuzz-base/base-builder-rust

# System deps the Zebra workspace needs beyond base-builder-rust:
#   - cmake / clang / libclang-dev : build the zcash_script C/C++ library reached
#     through the zebra-script FFI (script_verify / script_flag_matrix). rocksdb's
#     librocksdb-sys always runs bindgen, so libclang is a hard, workspace-wide
#     build dependency even when a system RocksDB is linked.
#   - protobuf-compiler : zebra-rpc pulls tonic, whose build script invokes protoc.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake clang libclang-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/robustfengbin/zebra-fuzz-m3 $SRC/zebra-fuzz
WORKDIR $SRC/zebra-fuzz
COPY build.sh $SRC/
