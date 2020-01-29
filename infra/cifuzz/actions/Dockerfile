# Copyright 2020 Google LLC
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
# Docker image to run CIFuzz in.

FROM ubuntu:16.04

RUN apt-get update && apt-get install -y git \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg2 \
    software-properties-common \
    python3


RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && apt-key fingerprint 0EBFCD88
RUN add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   xenial \
   stable"

RUN apt-get update && apt-get install docker-ce docker-ce-cli containerd.io -y

ENV OSS_FUZZ_ROOT=/opt/oss-fuzz
RUN git clone https://github.com/google/oss-fuzz.git ${OSS_FUZZ_ROOT}

# Copies your code file from  action repository to the container
COPY entrypoint.py /opt/entrypoint.py

# Python file to execute when the docker container starts up
ENTRYPOINT ["python3", "/opt/entrypoint.py"]
