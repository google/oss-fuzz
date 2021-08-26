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

RUN apt-get update && apt-get install -y \
    python3-pip \
    sudo

RUN pip3 install exodus-bundler

# Debug helpers.
RUN apt-get install -y vim

COPY install-nix.sh .
RUN sh install-nix.sh
ENV PATH="/root/.nix-profile/bin:${PATH}"

# Clone a fork to get a `clang` environment that works, which has not yet been integrated upstream;
# See https://github.com/NixOS/nix/pull/3160 .
RUN git clone --depth 1 --branch fuzzing_meson https://github.com/Pamplemousse/nix.git

# Bake the store in the image.
RUN \
  cd nix && \
  /root/.nix-profile/bin/nix \
    --experimental-features "nix-command flakes" \
    develop .\#.clang11StdenvPackages \
    --command echo 'success' && \
  cd -

COPY build.sh $SRC/

RUN apt autoremove -y \
      && rm -rf /var/lib/apt/lists/*

COPY extract-binary.sh .

# TODO: in the wait of having it integrated upstream.
COPY local.mk $SRC/nix/fuzz/
RUN echo "include fuzz/local.mk" >> $SRC/nix/Makefile
