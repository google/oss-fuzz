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

# Sparse-clone just the eBPF crate source from the Fuchsia monorepo.
# $SRC is /src in the OSS-Fuzz container. The project lands at
# $SRC/fuchsia-ebpf/ following the standard OSS-Fuzz Rust project layout.
RUN git clone --filter=blob:none --sparse \
        https://fuchsia.googlesource.com/fuchsia /tmp/fuchsia && \
    cd /tmp/fuchsia && \
    git sparse-checkout set src/starnix/lib/ebpf

RUN mkdir -p $SRC/fuchsia-ebpf
RUN cp -r /tmp/fuchsia/src/starnix/lib/ebpf/src $SRC/fuchsia-ebpf/src

# Synthetic Cargo manifests and shim crates (Fuchsia uses GN, not Cargo).
COPY ebpf_Cargo.toml   $SRC/fuchsia-ebpf/Cargo.toml
COPY linux_uapi/       $SRC/linux_uapi/
COPY fuchsia_sync/     $SRC/fuchsia_sync/

# cargo-fuzz workspace and crash-seed corpus.
COPY fuzz/             $SRC/fuchsia-ebpf/fuzz/
COPY seed_corpus/      $SRC/seed_corpus/

COPY build.sh $SRC/
