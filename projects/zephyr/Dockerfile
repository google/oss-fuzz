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

# Host build dependencies for the Zephyr / native_sim toolchain.
# (cmake and a recent clang are already provided by the base image.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ninja-build \
        gperf \
        device-tree-compiler \
        xz-utils \
        file \
        libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Zephyr's CMake (zephyr/cmake/modules/python.cmake) requires Python >= 3.12,
# but base-builder ships Python 3.11. Build 3.12 from source and front it
# ahead of the base image's interpreter on PATH. Same pattern base-builder
# uses for 3.11 (infra/base-images/base-builder/Dockerfile).
ENV ZEPHYR_PYTHON_VERSION=3.12.10
RUN apt-get update && apt-get install -y --no-install-recommends \
        zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev \
        libsqlite3-dev libreadline-dev libffi-dev libbz2-dev liblzma-dev \
 && unset CFLAGS CXXFLAGS \
 && cd /tmp \
 && curl -fsSLO https://www.python.org/ftp/python/$ZEPHYR_PYTHON_VERSION/Python-$ZEPHYR_PYTHON_VERSION.tar.xz \
 && tar -xf Python-$ZEPHYR_PYTHON_VERSION.tar.xz \
 && cd Python-$ZEPHYR_PYTHON_VERSION \
 && ./configure --prefix=/opt/python-3.12 --enable-shared --with-ensurepip=install \
 && make -j$(nproc) \
 && make install \
 && echo /opt/python-3.12/lib > /etc/ld.so.conf.d/python-3.12.conf \
 && ldconfig \
 && cd /tmp && rm -rf Python-$ZEPHYR_PYTHON_VERSION* \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /opt/python-3.12/bin/python3.12 /usr/local/bin/python3 \
 && ln -sf /opt/python-3.12/bin/python3.12 /usr/local/bin/python \
 && ln -sf /opt/python-3.12/bin/pip3.12   /usr/local/bin/pip3 \
 && ln -sf /opt/python-3.12/bin/pip3.12   /usr/local/bin/pip
ENV PATH=/opt/python-3.12/bin:$PATH

# Install west under Python 3.12 so its shebang and Zephyr's WEST_PYTHON
# both point at the 3.12 interpreter.
RUN /opt/python-3.12/bin/pip3.12 install --no-cache-dir west

# Initialize a Zephyr workspace and pull the modules pinned by the
# upstream west manifest. --narrow + --depth=1 keeps the checkout small
# while still giving us everything CMake needs to configure native_sim.
WORKDIR $SRC
RUN west init -m https://github.com/zephyrproject-rtos/zephyr.git \
        --mr main zephyrproject \
 && cd zephyrproject \
 && west update --narrow -o=--depth=1 \
 && west zephyr-export

RUN /opt/python-3.12/bin/pip3.12 install --no-cache-dir \
        -r $SRC/zephyrproject/zephyr/scripts/requirements-base.txt

WORKDIR $SRC/zephyrproject/zephyr
COPY build.sh $SRC/
