#!/usr/bin/python3
# Copyright 2023 Google LLC
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
FROM gcr.io/oss-fuzz-base/base-builder-python
RUN apt-get update && apt-get install -y npm libffi-dev
RUN python3 -m pip install --upgrade pip
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup install nightly
RUN rustup default nightly
RUN python3 -m pip install --upgrade pip cython notebook
RUN git clone --depth=1 https://github.com/python-jsonschema/jsonschema-specifications jsonschema_specifications
RUN git clone https://github.com/jupyter/nbclassic nbclassic
COPY *.sh *py $SRC/
WORKDIR $SRC/nbclassic
