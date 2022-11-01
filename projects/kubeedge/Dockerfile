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

FROM gcr.io/oss-fuzz-base/base-builder-go
RUN wget https://go.dev/dl/go1.17.5.linux-amd64.tar.gz --quiet && rm -rf /root/.go && mkdir /root/tmpgo && tar -C /root/tmpgo -xzf go1.17.5.linux-amd64.tar.gz && mv /root/tmpgo/go /root/.go && ldconfig
RUN git clone --depth 1 https://github.com/kubeedge/kubeedge
RUN git clone --depth 1 https://github.com/cncf/cncf-fuzzing
COPY build.sh $SRC/
WORKDIR $SRC/kubeedge
