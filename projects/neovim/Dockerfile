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

RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    gettext \
    libtool-bin \
    autoconf \
    automake \
    pkg-config \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/neovim/neovim $SRC/neovim

COPY build.sh \
     fuzz_nvim_vterm.c \
     fuzz_nvim_base64.c \
     fuzz_nvim_mpack.c \
     fuzz_nvim_vterm.dict \
     fuzz_nvim_base64.dict \
     fuzz_nvim_mpack.dict \
     $SRC/

WORKDIR $SRC/neovim
