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
#
##########################################################################

FROM gcr.io/oss-fuzz-base/base-builder-python

RUN pip3 install --disable-pip-version-check --no-cache-dir pip==24.2

# Pin the astroid version to 3.2.4 until Python 3.9+ is supported on OSS-Fuzz:
# https://github.com/google/oss-fuzz/pull/12027
RUN git clone --depth=1 --branch=v3.2.4 https://github.com/pylint-dev/astroid

COPY *.py *.sh "$SRC/"

WORKDIR "$SRC/astroid"
