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
RUN git clone --depth 1 https://github.com/lxml/lxml $SRC/lxml
RUN apt-get update && apt-get install -y zlib1g-dev make autoconf automake libtool pkg-config
RUN python3 -m pip install --upgrade pip \
    && python3 -m pip install 'setuptools>=42.0.0,<70.0.0' 'pyinstaller>=6.0.0,<7.0.0' -r $SRC/lxml/requirements.txt

COPY build.sh $SRC/
COPY fuzzer_configuration/ $SRC/fuzzer_configuration/
RUN git clone --depth 1 https://github.com/google/fuzzing \
    && cat fuzzing/dictionaries/html.dict \
        fuzzing/dictionaries/css.dict \
        fuzzing/dictionaries/svg.dict \
        fuzzing/dictionaries/xml.dict \
        fuzzing/dictionaries/rss.dict \
        fuzzing/dictionaries/xslt.dict \
        fuzzing/dictionaries/xpath.dict \
        fuzzing/dictionaries/regexp.dict \
      >> $SRC/fuzzer_configuration/dictionaries/__base.dict \
    && rm -rf fuzzing

# Upstream has at least one fuzz target that is not fully implemented from:
# https://github.com/lxml/lxml/pull/313 so the targets in this repo are coppied
# to a different directory to avoid confusion in build.sh.
COPY *.py $SRC/fuzz_targets/

WORKDIR $SRC/lxml
