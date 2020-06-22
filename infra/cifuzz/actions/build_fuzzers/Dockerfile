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

FROM gcr.io/oss-fuzz-base/cifuzz-base

# Copies your code file from  action repository to the container
COPY build_fuzzers_entrypoint.py /opt/build_fuzzers_entrypoint.py

# Python file to execute when the docker container starts up
ENTRYPOINT ["python3", "/opt/build_fuzzers_entrypoint.py"]
