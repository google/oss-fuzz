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

FROM gcr.io/oss-fuzz-base/base-builder-python

# Install dependencies for building Python from source
RUN apt-get update && apt-get install -y \
    build-essential \
    zlib1g-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    libssl-dev \
    libreadline-dev \
    libffi-dev \
    libsqlite3-dev \
    libbz2-dev \
    liblzma-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install Python 3.12 from source (Django main branch requires Python 3.12+)
RUN cd /tmp && \
    curl -O https://www.python.org/ftp/python/3.12.8/Python-3.12.8.tgz && \
    tar -xzf Python-3.12.8.tgz && \
    cd Python-3.12.8 && \
    ./configure --enable-optimizations --enable-shared --prefix=/usr/local/python3.12 && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/Python-3.12.8*

# Add Python 3.12 libs to LD_LIBRARY_PATH
ENV LD_LIBRARY_PATH="/usr/local/python3.12/lib:$LD_LIBRARY_PATH"

# Create symlinks for python3.12
RUN ln -sf /usr/local/python3.12/bin/python3.12 /usr/local/bin/python3.12 && \
    ln -sf /usr/local/python3.12/bin/pip3.12 /usr/local/bin/pip3.12

RUN python3.12 -m pip install --upgrade pip cython
RUN git clone --depth 1 https://github.com/django/django.git
RUN git clone --depth 1 https://github.com/django/django-fuzzers.git

COPY build.sh $SRC/

WORKDIR $SRC/django
