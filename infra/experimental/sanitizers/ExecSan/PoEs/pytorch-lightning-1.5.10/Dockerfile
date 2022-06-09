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
# Build and run the proof of error in pytorch-lightning.

FROM gcr.io/oss-fuzz-base/base-builder-python

RUN apt update && \
  apt install -y vim && \
  git clone \
    --depth 1 \
    --branch 1.5.10 \
    https://github.com/PyTorchLightning/pytorch-lightning.git

COPY ./build.sh $SRC
RUN  ./build.sh

COPY . $SRC
RUN make execSan

CMD ["make", "run"]
