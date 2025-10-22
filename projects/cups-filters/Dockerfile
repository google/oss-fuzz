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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool build-essential 

### for cups-filters-2.x
# RUN sed --in-place 's/focal/noble/g' /etc/apt/sources.list
# RUN apt update && apt-get install -y chrpath gnutls-dev libppd-dev libavahi-common-dev libavahi-client-dev autopoint gettext libcups2-dev ghostscript mupdf-tools 
# RUN git clone --depth 1 https://github.com/OpenPrinting/cups-filters.git

### for cups-filters-1.x
RUN apt update && apt-get install -y libexif-dev libglib2.0-dev libavahi-glib-dev liblcms2-dev libfreetype6-dev libfontconfig1-dev libqpdf-dev libpoppler-cpp-dev poppler-utils \
libunistring-dev libsystemd-dev libcap-dev gettext autopoint libcups2-dev libavahi-client-dev ghostscript mupdf-tools 

# ubuntu 20.04 only supports cups-filters 1.x
RUN git clone --depth 1 -b "1.x" https://github.com/OpenPrinting/cups-filters.git
RUN git clone --depth 1 https://github.com/OpenPrinting/fuzzing.git
        
RUN cp $SRC/fuzzing/projects/cups-filters/oss_fuzz_build.sh $SRC/build.sh

WORKDIR $SRC/cups-filters                   