# Copyright 2023 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

# Install prerequisite packages
# See connectedhomeip/docs/guides/BUILDING.md#prerequisites
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev libdbus-1-dev libglib2.0-dev libglib2.0-0\
        libavahi-client-dev ninja-build libmount-dev libblkid-dev \
        unzip libgirepository1.0-dev libcairo2-dev libreadline-dev patchelf file libevent-dev wget

# Install Rust for building `cryptography` python package when bootstraping pigweed
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup install nightly
RUN rustup default nightly

RUN git clone --depth=1 https://github.com/project-chip/connectedhomeip.git connectedhomeip

# PW_PROJECT_ROOT is used in requirements.build.txt
ENV PW_PROJECT_ROOT=$SRC/connectedhomeip

# Ensure global python has access to build requirements
RUN pip3 install -r connectedhomeip/scripts/setup/requirements.build.txt

# checkout submodules required for linux
RUN cd $SRC/connectedhomeip && scripts/checkout_submodules.py --shallow --platform linux

# Bootstrap pigweed environment
SHELL ["/bin/bash", "-c"]
RUN cd $SRC/connectedhomeip && . scripts/bootstrap.sh

# Work around the Fuzz Introspector build timeout (oss-fuzz#13153). base-builder's `compile` runs
# the introspector source analysis (tree-sitter parse of the whole tree + a per-harness call-graph
# pass) BEFORE build.sh. On connectedhomeip that is ~4h just to load ~32k files' trees, plus ~6h
# over the ~230 fuzz harnesses vendored under third_party -- together exceeding the build deadline.
# Because the analysis runs before build.sh, move third_party out of the source tree here (after
# bootstrap, which needs third_party/pigweed) so the analysis skips ~15k files and those ~230
# harnesses; build.sh moves it back before `gn gen`, so the actual asan/msan/coverage fuzz builds
# are unaffected. The stash dir is outside $SRC so the analysis (--target-dir=$SRC) never walks it.
# Also drop the dead all-clusters-minimal-app fuzz driver (a whole-application harness built by no
# target) so the analysis doesn't spend time on its Matter-wide call graph.
RUN cd $SRC/connectedhomeip && \
    rm -f examples/all-clusters-minimal-app/linux/fuzzing-main.cpp && \
    mv third_party /opt/chip-third-party-stash

# meson + packaging: GLib build deps for the MSAN dependency sysroot that build.sh builds when
# SANITIZER=memory (built there, not here -- the deps' configure/meson run instrumented binaries
# that need lowered ASLR, which only the privileged `compile` step provides).
RUN pip3 install meson packaging

COPY build.sh $SRC/
