#!/usr/bin/python3
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
"""Module for patching out coverage instrumentation for specific files."""

import os
import sys

with open(sys.argv[1], "r") as f:
  content = f.read()

patch_flag = False
new_content = ""
for line in content.split("\n"):
  if patch_flag:
    if "FLAGS =" in line:
      print("Patching")
      line = line.replace("-fprofile-instr-generate -fcoverage-mapping", "")
      patch_flag = False

  # Find the AMDGPUBaseInfo.cpp.o build
  if "build" in line and ("AMDGPUBaseInfo.cpp.o" in line or "AMDGPUMCCodeEmitter.cpp.o" in line):
    # Find the next flag
    patch_flag = True
  new_content += line + "\n"

with open(sys.argv[2], "w") as f:
  f.write(new_content)
