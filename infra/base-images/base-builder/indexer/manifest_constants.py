#!/usr/bin/env python3
# Copyright 2025 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Constants pertaining to snapshot manifests."""

# pylint: disable=g-import-not-at-top
try:
  import pathlib

  Path = pathlib.Path
except ImportError:
  import pathlib

  Path = pathlib.Path


# Source directory.
SRC_DIR = Path("src")
# Object directory.
OBJ_DIR = Path("obj")
# Directory for indexer data.
INDEX_DIR = Path("idx")
# Relative source file root in the index.
INDEX_RELATIVE_SOURCES = INDEX_DIR / "relative"
# Absolute source file root in the index.
INDEX_ABSOLUTE_SOURCES = INDEX_DIR / "absolute"
# The index database filename.
INDEX_DB = Path("db.sqlite")
# Library directory, where shared libraries are copied - inside obj.
LIB_DIR = OBJ_DIR / "lib"
# Manifest location
MANIFEST_PATH = Path("manifest.json")


# Where archive version 1 expects the lib directory to be mounted.
LIB_MOUNT_PATH_V1 = Path("/ossfuzzlib")

# Will be replaced with the input file for target execution.
INPUT_FILE = "<input_file>"
# A file the target can write output to.
OUTPUT_FILE = "<output_file>"
# Will be replaced with any dynamic arguments.
DYNAMIC_ARGS = "<dynamic_args>"

