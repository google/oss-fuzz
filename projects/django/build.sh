#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Make Python 3.12 the default python3 for this build
export PATH="/usr/local/python3.12/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/python3.12/lib:$LD_LIBRARY_PATH"
ln -sf /usr/local/python3.12/bin/python3.12 /usr/local/bin/python3
ln -sf /usr/local/python3.12/bin/pip3.12 /usr/local/bin/pip3

# Install atheris and pyinstaller for Python 3.12
python3 -m pip install atheris pyinstaller

# Build and install project (using current CFLAGS, CXXFLAGS). This is required
# for projects with C extensions so that they're built with the proper flags.
python3 -m pip install .

export DJANGO_SETTINGS_MODULE=fuzzer_project.settings

# Build fuzzers into $OUT. These could be detected in other ways.
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  compile_python_fuzzer $fuzzer --add-data django/conf/locale/en/LC_MESSAGES:django/conf/locale/en/LC_MESSAGES
done
