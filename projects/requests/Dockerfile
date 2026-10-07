# Copyright 2021 Google LLC
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

RUN git clone --depth 1 --branch main https://github.com/psf/requests.git requests \
    && python3 -m pip install --upgrade pip \
    && python3 -m pip install 'setuptools~=69.0' 'pyinstaller~=6.0' 'requests-mock~=1.0';

RUN mkdir -p $SRC/seed_data \
    && git clone --depth 1 https://github.com/DaveLak/oss-fuzz-inputs.git oss-fuzz-inputs \
    && rsync -avc oss-fuzz-inputs/requests/ $SRC/seed_data/ \
    && rm -rf oss-fuzz-inputs;

RUN git clone --depth 1 https://github.com/google/fuzzing fuzzing \
    && cat fuzzing/dictionaries/http.dict \
        fuzzing/dictionaries/url.dict \
      >> $SRC/seed_data/__base.dict \
    && rm -rf fuzzing;

COPY build.sh *.py $SRC/
WORKDIR $SRC/requests
