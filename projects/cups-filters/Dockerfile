# Copyright 2024 Google LLC
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
RUN apt-get update && apt-get install -y make autoconf automake libtool build-essential patchelf

RUN apt update && apt-get install -y zlib1g-dev libjpeg-dev libpng-dev libtiff-dev \
liblcms2-dev libfreetype6-dev libfontconfig1-dev fonts-dejavu-core libexif-dev libglib2.0-dev \
libavahi-glib-dev libavahi-client-dev libdbus-1-dev libqpdf-dev libunistring-dev libsystemd-dev \
libcap-dev gettext autopoint poppler-utils

RUN git clone --depth 1 https://github.com/OpenPrinting/cups.git
RUN git clone --depth 1 --recurse-submodules https://github.com/michaelrsweet/pdfio.git
RUN git clone --depth 1 https://github.com/OpenPrinting/libcupsfilters.git
RUN git clone --depth 1 https://github.com/OpenPrinting/libppd.git
RUN git clone --depth 1 https://github.com/OpenPrinting/cups-filters.git
RUN git clone --depth 1 https://github.com/OpenPrinting/fuzzing.git

RUN cp $SRC/fuzzing/projects/cups-filters/oss_fuzz_build.sh $SRC/build.sh

WORKDIR $SRC/cups-filters
COPY run_tests.sh $SRC/
