# Copyright 2025 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN git clone --depth 1 https://github.com/apache/kafka

RUN apt-get update && apt-get install -y wget software-properties-common
RUN wget -qO - https://packages.confluent.io/deb/7.0/archive.key | apt-key add -
RUN add-apt-repository "deb https://packages.confluent.io/clients/deb $(lsb_release -cs) main"
RUN apt-get update && apt-get install -y librdkafka-dev lsb-release gcc make

WORKDIR kafka
COPY build.sh $SRC/
COPY *.java $SRC/
