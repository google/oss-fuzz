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
        wget \
        libjpeg-dev \
        libtiff5-dev \
        libpng-dev \
        libfreetype6-dev \
        libgif-dev \
        libgtk-3-dev \
        libxml2-dev \
        libpango1.0-dev \
        libcairo2-dev \
        libspiro-dev \
        libuninameslist-dev \
        python3-dev \
        ninja-build \
        cmake \
        gettext \
        libc-dev \
        libgif-dev \
        liblzma-dev \
        libffi-dev  \
        libselinux1-dev 
RUN pip3 install -U meson ninja

RUN wget https://github.com/unicode-org/icu/releases/download/release-55-2/icu4c-55_2-src.tgz && tar xzvf icu4c-55_2-src.tgz

RUN git clone --depth=1 https://github.com/fontforge/fontforge
WORKDIR fontforge
COPY build.sh $SRC/
COPY fuzz_pdf.c $SRC/
