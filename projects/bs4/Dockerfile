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

# Held back because of github.com/google/oss-fuzz/pull/13407
# Please fix the build failure + upgrade.

FROM gcr.io/oss-fuzz-base/base-builder-python:ubuntu-24-04

RUN apt-get update && apt-get install -y bzr git libxslt-dev libxml2-dev zlib1g-dev
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install soupsieve html5lib lxml
RUN python3 -m pip install git+https://git.launchpad.net/beautifulsoup

COPY build.sh bs4_fuzzer.py $SRC/
