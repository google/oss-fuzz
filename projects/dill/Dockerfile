#!/usr/bin/python3
# Copyright 2023 Google LLC
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
# Held back because of github.com/google/oss-fuzz/pull/13407
# Please fix the build failure + upgrade.

FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:d223a882810372830fd7968eb3e64533f3a2318c90be43ac753a46a15946faec
RUN pip3 install --upgrade pip
RUN git clone https://github.com/uqfoundation/dill dill
COPY *.sh *py $SRC/
WORKDIR $SRC/dill
