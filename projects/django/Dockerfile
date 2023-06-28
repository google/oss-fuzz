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

RUN apt-get update -y && \
    apt-get install -y libgdal26 zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev libbz2-dev liblzma-dev

ENV PYTHON_VERSION 3.10.6
RUN cd /tmp && \
    curl -O https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tar.xz && \
    tar -xvf Python-$PYTHON_VERSION.tar.xz && \
    cd Python-$PYTHON_VERSION && \
    ./configure --enable-optimizations --enable-shared && \
    make -j install && \
    ldconfig && \
    rm -r /tmp/Python-$PYTHON_VERSION.tar.xz /tmp/Python-$PYTHON_VERSION

RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install cython "atheris>=2.1.1" "pyinstaller==5.0.1" "coverage==6.3.2"

RUN git clone --depth 1 https://github.com/django/django.git
RUN git clone --depth 1 https://github.com/django/django-fuzzers.git

COPY build.sh $SRC/

WORKDIR $SRC/django
