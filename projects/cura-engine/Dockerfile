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
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y ninja-build cmake chrpath
# TODO: Change this back to the Ultimaker repo
RUN git clone --depth 1 https://github.com/silvergasp/CuraEngine CuraEngine
RUN pip3 install conan==1.56
RUN conan config install https://github.com/ultimaker/conan-config.git
RUN conan profile new default --detect --force
RUN conan profile update settings.compiler.libcxx=libc++ default
RUN cp CuraEngine/tests/fuzz/oss-fuzz-build.sh $SRC/build.sh
WORKDIR CuraEngine