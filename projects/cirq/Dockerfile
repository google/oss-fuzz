# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder-python

RUN git clone \
    --depth 1 \
    --branch main \
    https://github.com/quantumlib/Cirq.git

WORKDIR $SRC/Cirq

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    grep -vhE '^#|^$' dev_tools/conf/apt-list-dev-tools.txt | \
    xargs -r apt-get install -y --no-install-recommends

# Install pip dependencies.
RUN --mount=type=cache,target=/root/.cache/pip \
    export PIP_ROOT_USER_ACTION=ignore && \
    pip3 install --upgrade pip && \
    pip3 install -r dev_tools/requirements/dev.env.txt

# Install Cirq-related modules.
RUN export PIP_ROOT_USER_ACTION=ignore && \
    pip3 install --no-cache-dir \
    ./cirq-core \
    ./cirq-aqt \
    ./cirq-web \
    ./cirq-ionq \
    ./cirq-google \
    ./cirq-pasqal

COPY build.sh fuzz_circuit.py $SRC/
