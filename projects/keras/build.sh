#!/bin/bash -eu
# Copyright 2023 Google Inc.
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
export ORIG_CFLAGS="$CFLAGS"
export ORIG_CXXFLAGS="$CXXFLAGS"
export CFLAGS=""
export CXXFLAGS=""
python3 -m pip install numpy
export CFLAGS=$ORIG_CFLAGS
export CXXFLAGS=$ORIG_CXXFLAGS
python3 -m pip install tf-nightly-cpu

# Rename to avoid the following: https://github.com/tensorflow/tensorflow/issues/40182
mv $SRC/tensorflow/tensorflow $SRC/tensorflow/tensorflow_src

compile_python_fuzzer $SRC/fuzz_serialization.py
compile_python_fuzzer $SRC/fuzz_model.py

zip $OUT/fuzz_model_seed_corpus.zip $SRC/hdf5-files/basic-model.h5
