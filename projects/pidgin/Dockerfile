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
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        make autoconf automake libtool pkg-config \
        zlib1g-dev zlib1g-dev:i386 liblzma-dev liblzma-dev:i386 \
        wget intltool  sasl2-bin python3-pip libpcre2-dev
RUN pip3 install -U meson ninja

RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/glib
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
RUN wget https://sourceforge.net/projects/pidgin/files/Pidgin/2.14.10/pidgin-2.14.10.tar.bz2
RUN wget ftp://sourceware.org/pub/libffi/libffi-3.2.1.tar.gz

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus
RUN git clone --depth 1 https://github.com/google/fuzzing

WORKDIR $SRC

COPY build.sh \	
     pidgin_xml_fuzzer.c \
     pidgin_utils_fuzzer.c \
     $SRC/
