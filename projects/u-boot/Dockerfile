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
    device-tree-compiler \
    python3-pyelftools \
    flex \
    bison \
    bc \
    libssl-dev \
    libgnutls28-dev \
    swig
RUN pip3 install jsonschema jinja2
RUN git clone --depth 1 https://github.com/u-boot/u-boot.git $SRC/u-boot
#ADD u-boot $SRC/u-boot
WORKDIR $SRC/u-boot
COPY efi_load_image.c $SRC/u-boot/test/fuzz/
COPY fit_image_load.c image_decomp.c $SRC/u-boot/test/fuzz/
COPY btrfs.c $SRC/u-boot/test/fuzz/
COPY oss-fuzz.patch $SRC/
COPY build.sh $SRC/
