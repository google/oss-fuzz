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

RUN apt-get install -y bzr python-lxml python-html5lib libxslt-dev libxml2-dev zlib1g-dev
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install soupsieve html5lib lxml
RUN python3 -m pip install bzr+lp:beautifulsoup

COPY build.sh bs4_fuzzer.py $SRC/
