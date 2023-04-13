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

import os
import sys
import atheris

with atheris.instrument_imports(enable_loader_override=False):
  from lxml import etree as et
  import xml.etree.ElementTree as etree

  #import etree
  import xdg.Menu
  from xdg.Exceptions import ParsingError

@atheris.instrument_func
def verify_xml(data):
  try:
    root = et.XML(data)
    if root != None:
      et.indent(root)
      et.ElementTree(root)
      return True
  except et.XMLSyntaxError:
    return False

@atheris.instrument_func
def TestOneInput(input_bytes):
  # This is a slight hack to verify xml with code
  # that gets instrumented. For some reason I was
  # unable to instrument xml itself.
  if not verify_xml(input_bytes):
    return

  # We need to make the file an absolute path
  testfile_path = os.path.join(os.getcwd(), "test.menu")
  with open(testfile_path, "wb") as f:
    f.write(input_bytes)

  try:
    xdg.Menu.parse(filename = testfile_path)
  except ParsingError:
    None
  except RecursionError: # Just catch it because it's not that interesting.
    None
  os.remove(testfile_path)

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
