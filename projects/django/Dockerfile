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

RUN apt-get update -y \
    && apt-get install -y libgdal26 software-properties-common \
    && add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get install -y python3.10 python3.10-dev \
    && curl -sS https://bootstrap.pypa.io/get-pip.py | python3.10 \
    && python3.10 -m pip install -v --no-cache-dir "atheris>=2.1.1" "pyinstaller==5.0.1" "coverage==6.3.2" \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/django/django.git
RUN git clone --depth 1 https://github.com/django/django-fuzzers.git

COPY build.sh $SRC/

WORKDIR $SRC/django
