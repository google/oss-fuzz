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

# Held back because of github.com/google/oss-fuzz/pull/12027
# Please fix failure and upgrade if possible.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:d8fe5e2a6a96723f393de413c48d9455a5124995b2349a2e4d6b9abecf99d6d5
RUN git clone https://github.com/pycrypto/pycrypto
COPY build.sh *.py $SRC/
WORKDIR pycrypto
