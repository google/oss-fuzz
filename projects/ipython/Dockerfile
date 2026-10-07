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

FROM gcr.io/oss-fuzz-base/base-builder-python:ubuntu-24-04
RUN apt-get update && apt-get install -y python3.12 python3.12-dev python3.12-venv && \
    rm -f /usr/lib/python3.12/EXTERNALLY-MANAGED && \
    update-alternatives --install /usr/local/bin/python3 python3 /usr/bin/python3.12 1 && \
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3 && \
    python3 -m pip install pyinstaller atheris
RUN git clone --depth 1 https://github.com/ipython/ipython
WORKDIR $SRC
COPY build.sh fuzz_* $SRC/
