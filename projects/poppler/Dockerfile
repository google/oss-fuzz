# Copyright 2018 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN git clone --depth 1 --single-branch https://gitlab.freedesktop.org/poppler/poppler.git
RUN sed -i '/apt-get install/s/\bpython\b/python-is-python3/' $SRC/poppler/test/ossfuzz/prepare_build.sh && \
    $SRC/poppler/test/ossfuzz/prepare_build.sh && \
    git -C $SRC/poppler checkout -- test/ossfuzz/prepare_build.sh
RUN cp $SRC/poppler/test/ossfuzz/build_fuzzers.sh $SRC/build.sh
