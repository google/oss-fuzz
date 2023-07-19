#!/bin/bash -eu
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

# Build and install project (using current CFLAGS, CXXFLAGS).
cd lightning
git apply <<EOF
diff --git a/requirements.txt b/requirements.txt
index dd34e9273..36f55e683 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,7 +1,7 @@
 # the default package dependencies

 numpy>=1.17.2
-torch>=1.7.*
+torch>=1.7.1
 future>=0.17.1  # required for builtins in setup.py
 tqdm>=4.41.0
 PyYAML>=5.1
diff --git a/requirements/examples.txt b/requirements/examples.txt
index 8591f9bd5..8c0d96bd1 100644
--- a/requirements/examples.txt
+++ b/requirements/examples.txt
@@ -1,3 +1,3 @@
-torchvision>=0.8.*
+torchvision>=0.8.2
 gym>=0.17.0
 ipython[all]
diff --git a/requirements/extra.txt b/requirements/extra.txt
index 74743185e..52580b475 100644
--- a/requirements/extra.txt
+++ b/requirements/extra.txt
@@ -2,7 +2,7 @@

 matplotlib>3.1
 horovod>=0.21.2  # no need to install with [pytorch] as pytorch is already installed
-torchtext>=0.8.*
+torchtext>=0.8.1
 omegaconf>=2.0.5
 hydra-core>=1.0.5
 jsonargparse[signatures]>=4.0.4,<5.0.0
EOF
pip3 install --upgrade pip
pip3 install .

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  compile_python_fuzzer $fuzzer
done
