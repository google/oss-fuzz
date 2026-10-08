# Copyright 2026 Atomicorp, Inc. / Google LLC
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
RUN apt-get update && apt-get install -y make zip
# Prefer the harness branch until https://github.com/ossec/ossec-hids/pull/2342 merges.
RUN git clone --depth 1 --branch feature/1789-oss-fuzz \
      https://github.com/atomicturtle/ossec-hids.git ossec-hids \
  || git clone --depth 1 https://github.com/ossec/ossec-hids.git ossec-hids
WORKDIR $SRC/ossec-hids
COPY build.sh $SRC/
