# Copyright 2016 Google Inc.
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
"""Templates for OSS-Fuzz project files."""

PROJECT_YAML_TEMPLATE = """\
homepage: "<your_project_homepage>"
language: %(language)s
primary_contact: "<primary_contact_email>"
main_repo: "https://path/to/main/repo.git"
file_github_issue: true
"""

DOCKER_TEMPLATE = """\
# Copyright %(year)d Google LLC
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

FROM gcr.io/oss-fuzz-base/%(base_builder)s
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 <git_url> %(project_name)s     # or use other version control
WORKDIR %(project_name)s
COPY build.sh $SRC/
"""

EXTERNAL_DOCKER_TEMPLATE = """\
FROM gcr.io/oss-fuzz-base/%(base_builder)s:v1
RUN apt-get update && apt-get install -y make autoconf automake libtool
COPY . $SRC/%(project_name)s
WORKDIR %(project_name)s
COPY .clusterfuzzlite/build.sh $SRC/
"""

BUILD_TEMPLATE = """\
#!/bin/bash -eu
# Copyright %(year)d Google LLC
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

# build project
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \\
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \\
#     $LIB_FUZZING_ENGINE /path/to/library.a
"""

EXTERNAL_BUILD_TEMPLATE = """\
#!/bin/bash -eu

# build project
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \\
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \\
#     $LIB_FUZZING_ENGINE /path/to/library.a
"""

EXTERNAL_PROJECT_YAML_TEMPLATE = """\
language: %(language)s
"""

TEMPLATES = {
    'build.sh': BUILD_TEMPLATE,
    'Dockerfile': DOCKER_TEMPLATE,
    'project.yaml': PROJECT_YAML_TEMPLATE
}

EXTERNAL_TEMPLATES = {
    'build.sh': EXTERNAL_BUILD_TEMPLATE,
    'Dockerfile': EXTERNAL_DOCKER_TEMPLATE,
    'project.yaml': EXTERNAL_PROJECT_YAML_TEMPLATE
}
