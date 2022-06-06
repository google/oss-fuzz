# Copyright 2022 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#      http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build and run the proof of error in python-libnmap.

FROM gcr.io/oss-fuzz-base/base-clang

RUN apt update && \
  apt install -y \
  wget \
  python3 \
  python3-pip \
  nmap && \
  wget https://github.com/savon-noir/python-libnmap/archive/refs/tags/v0.7.2.tar.gz -O python-libnmap-0.7.2.tar.gz && \
  tar -xf python-libnmap-0.7.2.tar.gz && \
  cd python-libnmap-0.7.2 && \
  pip3 install -e . && \
  mkdir /CVE

WORKDIR /CVE

COPY . /CVE

CMD ["make", "libnmap"]

