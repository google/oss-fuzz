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

with atheris.instrument_imports(include=["lxml.etree", "lxml"]):
  from lxml import etree as et


def TestOneInput(data):
  tree = None
  success = False
  try:
    root = et.XML(data)
    if root != None:
      et.indent(root)

      tree = et.ElementTree(root)
      success = True
  except et.XMLSyntaxError:
    return -1  # Reject so the input will not be added to the corpus.

  if success:
    try:
      a = et.Element("a")
      tree.getelementpath(a)
    except ValueError:
      return -1  # Reject so the input will not be added to the corpus.


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
