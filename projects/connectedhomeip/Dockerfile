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

# TODO(MSAN, DO NOT MERGE as-is): until the chip-side MSAN-fuzz changes land upstream, clone the
# fork branch that carries `scripts/build/build_msan_sysroot.sh --oss-fuzz` (used by the sysroot
# bake below) and the MSAN fuzz wiring. Revert to project-chip/connectedhomeip master once merged.
RUN git clone --depth=1 -b AA/msan-fuzztests https://github.com/Alami-Amine/connectedhomeip.git connectedhomeip

# PW_PROJECT_ROOT is used in requirements.build.txt
ENV PW_PROJECT_ROOT=$SRC/connectedhomeip

# Ensure global python has access to build requirements
RUN pip3 install -r connectedhomeip/scripts/setup/requirements.build.txt

# checkout submodules required for linux
RUN cd $SRC/connectedhomeip && scripts/checkout_submodules.py --shallow --platform linux

# Bootstrap pigweed environment
SHELL ["/bin/bash", "-c"]
RUN cd $SRC/connectedhomeip && . scripts/bootstrap.sh

# Tooling for the MSAN-instrumented dependency sysroot that build.sh builds when
# SANITIZER=memory (see build.sh). The sysroot is built in build.sh -- NOT here -- because the
# deps' ./configure / meson run MSAN-instrumented test binaries, which require ASLR entropy to be
# lowered (vm.mmap_rnd_bits=28). The OSS-Fuzz `compile` wrapper sets that and runs the build
# privileged; `docker build` can neither sysctl nor disable ASLR (seccomp blocks personality()),
# so a Dockerfile-time bake fails intermittently. meson + the python `packaging` module are
# GLib's build requirements; ninja/wget/pkg-config were installed above.
RUN pip3 install meson packaging

COPY build.sh $SRC/
