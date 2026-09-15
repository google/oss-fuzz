#!/bin/bash -eu
# SPDX-FileCopyrightText: 2026 RAWx18 <rawx18.dev@gmail.com>
# SPDX-License-Identifier: Apache-2.0

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

# The fuzz targets import directly from the checkout. PyInstaller needs each
# source root and the model catalogue used by observal_shared.
REPO_DIR="$SRC/observal"
FUZZ_DIR="$REPO_DIR/fuzz"
SERVER_DIR="$REPO_DIR/observal-server"
SHARED_DIR="$REPO_DIR/packages/observal-shared"

for fuzzer in "$FUZZ_DIR"/*_fuzzer.py; do
  target="$(basename -s .py "$fuzzer")"

  compile_python_fuzzer "$fuzzer" \
    --paths="$REPO_DIR" \
    --paths="$SERVER_DIR" \
    --paths="$SHARED_DIR" \
    --add-data="$SHARED_DIR/observal_shared/harness_models:observal_shared/harness_models"

  if [[ -d "$FUZZ_DIR/corpus/$target" ]]; then
    zip -j "$OUT/${target}_seed_corpus.zip" "$FUZZ_DIR/corpus/$target"/*
  fi

  if [[ -f "$FUZZ_DIR/dictionaries/${target}.dict" ]]; then
    cp "$FUZZ_DIR/dictionaries/${target}.dict" "$OUT/${target}.dict"
  fi
done
