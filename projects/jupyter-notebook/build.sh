#!/bin/bash -eu
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

# Installa dipendenze
pip install -r $SRC/requirements.txt

# Installa Atheris
pip install atheris

# Copia fuzz target
cp $SRC/projects/jupyter-notebook/fuzz_notebook.py $OUT/

# Crea seed corpus (il tuo PoC RCE)
mkdir -p $OUT/corpus
echo "__import__('os').system('id')" > $OUT/corpus/seed1.py

# Build (Python fuzzers sono script)
cp $OUT/fuzz_notebook.py $OUT/fuzz_notebook
