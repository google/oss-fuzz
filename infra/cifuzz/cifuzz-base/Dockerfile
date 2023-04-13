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

FROM gcr.io/oss-fuzz-base/base-runner

RUN apt-get update && \
    apt-get install -y systemd && \
    wget https://download.docker.com/linux/ubuntu/dists/focal/pool/stable/amd64/docker-ce-cli_20.10.8~3-0~ubuntu-focal_amd64.deb -O /tmp/docker-ce.deb && \
    dpkg -i /tmp/docker-ce.deb && \
    rm /tmp/docker-ce.deb && \
    mkdir -p /opt/gcloud && \
    wget -qO- https://dl.google.com/dl/cloudsdk/release/google-cloud-sdk.tar.gz | tar zxv -C /opt/gcloud && \
    /opt/gcloud/google-cloud-sdk/install.sh --usage-reporting=false --bash-completion=false --disable-installation-options && \
    apt-get -y install gcc python3-dev && \
    pip3 install -U crcmod && \
    apt-get autoremove -y gcc python3-dev


ENV PATH=/opt/gcloud/google-cloud-sdk/bin/:$PATH
ENV OSS_FUZZ_ROOT=/opt/oss-fuzz

# Do this step before copying to make rebuilding faster when developing.
COPY ./infra/cifuzz/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt

ADD . ${OSS_FUZZ_ROOT}
# Don't use the default npm location since jazzer.js can break us.
# This means javascript needed by cifuzz/clusterfuzzlite must be executed in
# OSS_FUZZ_ROOT.
RUN cd ${OSS_FUZZ_ROOT} && npm install ${OSS_FUZZ_ROOT}/infra/cifuzz


ENV PYTHONUNBUFFERED=1

# Python file to execute when the docker container starts up.
# We can't use the env var $OSS_FUZZ_ROOT here. Since it's a constant env var,
# just expand to '/opt/oss-fuzz'.
ENTRYPOINT ["python3", "/opt/oss-fuzz/infra/cifuzz/cifuzz_combined_entrypoint.py"]
