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


FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends     cmake ninja-build make pkg-config zlib1g-dev python3 &&     rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/DCMTK/dcmtk $SRC/dcmtk
RUN git clone --depth 1 https://github.com/DCMTK/dcmtk-fuzzers $SRC/dcmtk-fuzzers

COPY build.sh $SRC/
COPY dcmtk_dicom_fuzzer.dict make_seed_corpus.py $SRC/dcmtk-fuzzers/
COPY dcmtk_dicom_fuzzer.cc dcmtk_meta_fuzzer.cc $SRC/dcmtk-fuzzers/

WORKDIR $SRC/dcmtk-fuzzers
