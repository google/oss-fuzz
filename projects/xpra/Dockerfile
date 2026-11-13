# Copyright 2026 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-python:ubuntu-24-04

# xpra requires Python >= 3.12, newer than the one in the base image:
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3.12 python3.12-dev python3.12-venv \
        pkg-config liblz4-dev libbrotli-dev libzstd-dev libxxhash-dev && \
    rm -f /usr/lib/python3.12/EXTERNALLY-MANAGED && \
    update-alternatives --install /usr/local/bin/python3 python3 /usr/bin/python3.12 1 && \
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3 && \
    python3 -m pip install cython "pyinstaller==6.10.0" "setuptools==72.1.0" && \
    # build atheris against the toolchain's libFuzzer, as `install_python.sh` does:
    CFLAGS= CXXFLAGS= \
    LIBFUZZER_LIB=$(echo /usr/local/lib/clang/*/lib/x86_64-unknown-linux-gnu/libclang_rt.fuzzer_no_main.a) \
    python3 -m pip install --no-cache-dir --no-binary atheris atheris

RUN git clone --depth 1 https://github.com/Xpra-org/xpra.git xpra
WORKDIR $SRC/xpra
COPY build.sh $SRC/
