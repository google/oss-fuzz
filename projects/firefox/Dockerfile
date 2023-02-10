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
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository -y ppa:ubuntu-toolchain-r/test && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      cmake \
      gawk \
      git \
      libstdc++6 \
      m4 \
      nasm \
      python \
      python3-pip \
      python3-setuptools \
      python3-wheel

# install Firefox deps
# built using https://packages.ubuntu.com/focal/firefox as a reference
RUN apt-get install -y --no-install-recommends \
    libasound2 \
    libatk1.0-0 \
    libc6 \
    libcairo-gobject2 \
    libcairo2 \
    libdbus-1-3 \
    libdbus-glib-1-2 \
    libffi7 \
    libfontconfig1 \
    libfreetype6 \
    libgcc-s1 \
    libgdk-pixbuf2.0-0 \
    libglib2.0-0 \
    libgtk-3-0 \
    libharfbuzz0b \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libpangoft2-1.0-0 \
    libstdc++6 \
    libx11-6 \
    libx11-xcb1 \
    libxcb-shm0 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxt6 \
    libxtst6 \
    lsb-release \
    libcanberra0 \
    libdbusmenu-glib4 \
    libdbusmenu-gtk3-4

RUN pip3 install meson ninja

# This wrapper of cargo seems to interfere with our build system.
RUN rm -f /usr/local/bin/cargo

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > $SRC/rustbuild.sh && \
    chmod +x $SRC/rustbuild.sh && \
    $SRC/rustbuild.sh -y

RUN git clone --depth 1 https://github.com/mozilla/gecko-dev mozilla-central
RUN git clone --depth 1 https://github.com/mozillasecurity/fuzzdata
WORKDIR mozilla-central
# Install OS dependencies.
# Will be re-run in build.sh to install missing dependencies.
ENV SHELL /bin/bash
RUN ./mach --no-interactive bootstrap --application-choice browser
COPY build.sh target.c *.options mozconfig.* $SRC/
