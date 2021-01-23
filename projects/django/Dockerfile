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
RUN apt-get install -y build-essential libncursesw5-dev libreadline-dev libssl-dev libgdbm-dev libc6-dev libsqlite3-dev tk-dev libbz2-dev zlib1g-dev libffi-dev wget
RUN wget -q https://github.com/python/cpython/archive/v3.8.7.tar.gz
RUN git clone --depth 1 https://github.com/django/django-fuzzers.git
RUN git clone --depth 1 https://github.com/django/django.git
COPY build.sh $SRC/
