#!/usr/bin/python3
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

import atheris
import sys
import os
with atheris.instrument_imports():
    from smart_open import parse_uri
    from smart_open import register_compressor

def _handle_file(file_obj, mode):
    return open(file_obj,mode)

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)
   
    parse_uri(fdp.ConsumeString(200))
    register_compressor(".%s"%fdp.ConsumeString(3),_handle_file)

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
  main()
