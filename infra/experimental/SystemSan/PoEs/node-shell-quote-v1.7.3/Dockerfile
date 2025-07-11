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
# Build and run the proof of error in shell-quote v1.7.3.

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt update && \
  apt install -y \
  vim \
  npm && \
  git clone \
    https://github.com/ljharb/node-shell-quote.git && \
  cd node-shell-quote && \
  # v1.7.3 is not tagged anymore
  git reset --hard 6a8a899c62a58a30fb128a7079f02826ed4faee0 && \
  npm config set @gitlab-org:registry \
    https://gitlab.com/api/v4/packages/npm/

COPY ./build.sh $SRC
RUN  ./build.sh

COPY . $SRC
RUN make SystemSan

CMD ["make", "run"]
