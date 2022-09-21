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

FROM gcr.io/oss-fuzz-base/base-builder-python

RUN apt-get update -y && apt-get install -y wget software-properties-common
RUN wget -qO - https://packages.confluent.io/deb/7.0/archive.key | apt-key add -
RUN add-apt-repository "deb https://packages.confluent.io/clients/deb $(lsb_release -cs) main"
RUN apt-get update -y && apt-get install librdkafka-dev software-properties-common lsb-release gcc make python3-dev libsasl2-modules-gssapi-mit krb5-user -y

RUN pip3 install --upgrade pip

RUN git clone --depth=1 https://github.com/confluentinc/confluent-kafka-python kafka
WORKDIR kafka

COPY build.sh fuzz_*.py $SRC/
