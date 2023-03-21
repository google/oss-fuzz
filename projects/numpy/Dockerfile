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

FROM gcr.io/oss-fuzz-base/base-builder-python

# Ensure we work from right python version
RUN apt-get install -y python3.9 python3.9-dev && \
    ln --force -s /usr/bin/python3.9 /usr/local/bin/python3 && \
    apt-get install -y python3-pip && \
    python3 -m pip install cython "atheris>=2.1.1" "pyinstaller==5.0.1" "coverage==6.3.2"

RUN git clone https://github.com/numpy/numpy && cd numpy && git submodule update --init
WORKDIR $SRC
COPY *.py build.sh $SRC/
