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

FROM gcr.io/oss-fuzz-base/base-builder

# hobbes is an embedded compiler and JIT built on LLVM. The base image's LLVM
# is not installed as a development package, so take a versioned one from
# apt.llvm.org; 18 is covered by the project's own CI matrix.
ENV HOBBES_LLVM_VERSION=18

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake make python3 zip \
        zlib1g-dev libncurses-dev libzstd-dev libreadline-dev \
        wget gnupg lsb-release software-properties-common && \
    wget -qO- https://apt.llvm.org/llvm.sh | bash -s -- $HOBBES_LLVM_VERSION && \
    apt-get install -y --no-install-recommends llvm-$HOBBES_LLVM_VERSION-dev && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/morganstanley/hobbes.git $SRC/hobbes

WORKDIR $SRC/hobbes
COPY build.sh $SRC/
