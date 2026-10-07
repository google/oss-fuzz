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
RUN apt install -y nodejs
RUN pip3 install --upgrade pip
RUN curl -sL https://deb.nodesource.com/setup_10.x -o nodesource_setup.sh
RUN git clone https://github.com/jupyter/jupyter_events $SRC/jupyter_events
RUN bash nodesource_setup.sh
RUN apt install -y nodejs
RUN git clone https://github.com/jupyter-server/jupyter_server/
COPY build.sh *.py $SRC/
WORKDIR jupyter_server
