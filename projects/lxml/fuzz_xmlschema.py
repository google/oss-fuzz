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
import io

with atheris.instrument_imports():
  from lxml import etree as et


def TestOneInput(data):
  """Targets XML schema validation. More APIs should be added"""
  try:
    schema_raw = et.parse(io.BytesIO(data))
    valid_tree = et.parse(io.BytesIO('<a><b></b></a>'))
    
    schema = etree.XMLSchema(schema_raw)
    schame.validate(valid_tree)
  except et.LxmlError:
    None

def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
