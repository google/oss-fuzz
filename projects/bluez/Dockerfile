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
    make autoconf automake libtool pkg-config \
    libdbus-1-dev  libreadline8 libreadline-dev \
    python-docutils libudev-dev udev libical-dev \
    libdbus-1-dev systemd

RUN pip3 install -U meson ninja
RUN git clone --depth 1 https://github.com/bluez/bluez bluez
RUN git clone https://github.com/GNOME/glib  && \
    cd glib && \
    meson _build -Db_lundef=false -Ddefault_library=static -Dlibmount=disabled && \
    ninja -C _build && \
    ninja -C _build install
WORKDIR bluez
COPY build.sh $SRC/
COPY *.c $SRC/
