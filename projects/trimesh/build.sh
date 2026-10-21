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
#
################################################################################

# Build trimesh and its fuzz targets for OSS-Fuzz.

cd "$SRC/trimesh"

# `easy` pulls the pure-python and lightweight native extras (lxml, pillow,
# shapely) without the heavy viewer/CAD stack. That keeps the build reproducible
# while still reaching the XML and image-backed loaders.
pip3 install --no-cache-dir '.[easy]'

# compile_python_fuzzer is provided by base-builder-python; it wraps each target
# with Atheris and emits the driver OSS-Fuzz expects. Anything after the fuzzer
# path is forwarded verbatim to PyInstaller.
#
# --collect-submodules=numpy is required, not optional. PyInstaller's static
# import analysis misses numpy 2.x's `numpy._core.*`, so the binary builds
# cleanly and then dies at startup with "No module named
# numpy._core._exceptions". check_build catches it; a plain build does not.
#
# trimesh is collected for the same class of reason: its optional-format loaders
# are wired up through try/except imports that static analysis cannot follow.
for fuzzer in "$SRC"/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer" \
    --collect-submodules=numpy \
    --collect-submodules=trimesh
done

# Seed corpora. Real files give the fuzzer valid structure to mutate from —
# without them it spends most of its budget failing the magic-number check.
mkdir -p "$WORK/seeds"
find "$SRC/trimesh/models" -maxdepth 1 -type f \
     \( -name '*.stl' -o -name '*.obj' -o -name '*.ply' -o -name '*.off' \
        -o -name '*.dae' -o -name '*.3mf' -o -name '*.glb' -o -name '*.xyz' \) \
     -exec cp {} "$WORK/seeds/" \; 2>/dev/null || true

if [ -n "$(ls -A "$WORK/seeds" 2>/dev/null)" ]; then
  zip -j -q "$OUT/fuzz_load_seed_corpus.zip" "$WORK"/seeds/*
fi

# The archive target wants zip/tar inputs specifically.
mkdir -p "$WORK/zseeds"
find "$SRC/trimesh/models" -maxdepth 1 -type f \
     \( -name '*.zip' -o -name '*.tar*' -o -name '*.3mf' \) \
     -exec cp {} "$WORK/zseeds/" \; 2>/dev/null || true

if [ -n "$(ls -A "$WORK/zseeds" 2>/dev/null)" ]; then
  zip -j -q "$OUT/fuzz_compressed_seed_corpus.zip" "$WORK"/zseeds/*
fi
