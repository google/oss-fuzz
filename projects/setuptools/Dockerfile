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
RUN git clone --depth 1 --single-branch https://github.com/pypa/setuptools setuptools
RUN git clone --depth 1 --single-branch https://github.com/pypa/distutils distutils
RUN python3 -m pip install --upgrade pip \
    && python3 -m pip install 'pyinstaller==6.10.0' tomli tomli-w railroad-diagrams pyparsing jinja2
RUN urls="\
https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/utf8.dict \
https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/toml.dict" \
  && target_file="$SRC/__base.dict" \
  && echo $urls | xargs -n 1 wget -qO- >> $target_file
COPY *.sh *py $SRC/
WORKDIR $SRC/setuptools
