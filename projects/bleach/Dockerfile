# Copyright 2021 Google Inc.
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

RUN git clone \
	--depth 1 \
	--branch main \
	https://github.com/mozilla/bleach.git

WORKDIR bleach

RUN git clone --depth 1 https://github.com/google/fuzzing
RUN cat fuzzing/dictionaries/html.dict > $OUT/linkify_fuzzer.dict
RUN cat fuzzing/dictionaries/html.dict > $OUT/sanitize_fuzzer.dict

COPY build.sh sanitize_fuzzer.py linkify_fuzzer.py $SRC/
