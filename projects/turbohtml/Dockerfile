# Copyright 2026 Google LLC
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
RUN python3 -m pip install --no-cache-dir 'meson>=1.12.1' 'meson-python>=0.22.1' 'ninja>=1.13.2' 'html5lib>=1.1' \
    'markdown-it-py>=4.2' 'tinycss2>=1.5.1' 'typing-extensions>=4.16'
RUN git clone --depth 1 https://github.com/tox-dev/turbohtml $SRC/turbohtml
WORKDIR $SRC/turbohtml
COPY build.sh $SRC/
