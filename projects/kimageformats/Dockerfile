# Copyright 2018 Google Inc.
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
RUN apt-get update && apt-get install --yes cmake make autoconf automake autopoint libtool wget po4a ninja-build pkgconf
RUN git clone --depth 1 https://github.com/madler/zlib.git
RUN git clone --depth 1 -b v1.5.7 https://github.com/facebook/zstd.git
RUN git clone --depth 1 https://github.com/nih-at/libzip.git
RUN wget https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz
RUN git clone https://github.com/tukaani-project/xz.git
RUN git clone --depth 1 --branch=RB-3.3 https://github.com/AcademySoftwareFoundation/openexr.git
RUN git clone --depth 1 -b master https://invent.kde.org/frameworks/extra-cmake-modules.git
RUN git clone --depth 1 --branch=dev git://code.qt.io/qt/qtbase.git
RUN git clone --depth 1 -b master https://invent.kde.org/frameworks/karchive.git
RUN git clone --depth 1 -b master https://invent.kde.org/frameworks/kimageformats.git
RUN git clone --depth 1 -b v3.12.0 https://aomedia.googlesource.com/aom
RUN git clone --depth 1 -b v1.2.1 https://github.com/AOMediaCodec/libavif.git
RUN git clone --depth 1 https://github.com/strukturag/libde265.git
RUN git clone --depth 1 -b v2.5.3 https://github.com/uclouvain/openjpeg.git
RUN git clone --depth 1 https://github.com/strukturag/libheif.git
RUN git clone --depth=1 --branch v0.11.x --recursive --shallow-submodules https://github.com/libjxl/libjxl.git
RUN git clone --depth 1 https://github.com/LibRaw/LibRaw
RUN git clone --depth 1 https://github.com/mircomir/jxrlib.git
RUN git clone --depth 1 -b v2.6.0 https://github.com/cisco/openh264.git
COPY build.sh kimgio_fuzzer.cc $SRC/
WORKDIR $SRC/kimageformats
