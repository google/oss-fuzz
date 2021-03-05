# Copyright 2020 Google Inc.
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
RUN apt-get update && apt-get install -y make autoconf automake libtool \
    libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev patchelf wget \
    libattr1 libattr1-dev libcap-ng-dev
# Ninja in the apt repos is too old. Get it directly from github
RUN wget https://github.com/ninja-build/ninja/releases/latest/download/ninja-linux.zip \
    && unzip ninja-linux.zip \
    && rm ninja-linux.zip \
    && mv ninja /usr/bin/ninja
RUN git clone --depth 1 https://git.qemu.org/git/qemu.git qemu
WORKDIR qemu
RUN cp scripts/oss-fuzz/build.sh $SRC
