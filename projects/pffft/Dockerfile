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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y mercurial python-numpy python
RUN git clone https://bitbucket.org/jpommier/pffft $SRC/pffft
WORKDIR pffft
COPY build.sh $SRC
# TODO(alessiob): Move the fuzzing source code to pffft upstream.
COPY generate_seed_corpus.py $SRC/pffft
COPY pffft_fuzzer.cc $SRC/pffft
