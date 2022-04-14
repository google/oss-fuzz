# Copyright 2022 Google LLC
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
    make \
    autoconf \
    pkg-config \
    automake \
    software-properties-common \
    wget \
    liblzma-dev \
    libffi-dev \
    libext2fs-dev \
    libgpgme-dev libfuse-dev \
    python3-pip \
    libtool \
    bison
RUN unset CFLAGS CXXFLAGS && pip3 install -U meson ninja
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/glib
RUN git clone https://github.com/ostreedev/ostree && \
    cd ostree && \
    git submodule update --init
COPY build.sh $SRC/
COPY fuzz*.c $SRC/
