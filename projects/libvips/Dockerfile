# Copyright 2019 Google Inc.
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
  automake \
  autopoint \
  cmake \
  curl \
  gettext \
  glib2.0-dev \
  libbrotli-dev \
  libexpat1-dev \
  libffi-dev \
  libfftw3-dev \
  libgflags-dev \
  libselinux1-dev \
  libtool \
  nasm \
  python3-pip
RUN pip3 install meson ninja
RUN mkdir afl-testcases
RUN curl https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz | tar xzC afl-testcases
RUN mkdir pdfium-latest
RUN curl -L https://github.com/bblanchon/pdfium-binaries/releases/latest/download/pdfium-linux-x64.tgz | tar xzC pdfium-latest
RUN git clone --depth 1 https://github.com/libvips/libvips.git
RUN git clone --depth 1 https://github.com/madler/zlib.git
RUN git clone --depth 1 https://github.com/libexif/libexif.git
RUN git clone --depth 1 https://github.com/mm2/Little-CMS.git lcms
RUN git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo.git
RUN git clone --depth 1 https://github.com/glennrp/libpng.git
RUN git clone --depth 1 https://github.com/randy408/libspng.git
RUN git clone --depth 1 https://chromium.googlesource.com/webm/libwebp
RUN git clone --depth 1 https://gitlab.com/libtiff/libtiff.git
RUN git clone --depth 1 https://aomedia.googlesource.com/aom
RUN git clone --depth 1 https://github.com/strukturag/libheif.git
RUN git clone --depth 1 --recursive https://github.com/libjxl/libjxl.git
RUN git clone --depth 1 https://github.com/lovell/libimagequant.git
RUN git clone --depth 1 https://github.com/dloebl/cgif.git

WORKDIR libvips
COPY build.sh $SRC/
# This is to fix Fuzz Introspector build by using LLVM old pass manager
# re https://github.com/ossf/fuzz-introspector/issues/305
ENV OLD_LLVMPASS 1
