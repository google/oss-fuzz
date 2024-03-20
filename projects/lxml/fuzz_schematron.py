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
  from lxml import etree
  from lxml.isoschematron import Schematron


def TestOneInput(data):
  """Targets Schematron. Currently validates, but we should add more APIs"""
  try:
    schema_raw = etree.parse(io.BytesIO(data))
    valid_tree = etree.parse(io.BytesIO(b"<AAA><BBB/><CCC/></AAA>"))

    schematron = Schematron(schema_raw)
    schematron.validate(valid_tree)
  except (etree.LxmlError, KeyError) as e:
    if isinstance(e, etree.LxmlError) or (
        isinstance(e, KeyError) and "None" in str(e)
        # This possibility is tracked here: https://bugs.launchpad.net/lxml/+bug/2058177
    ):
      return -1  # Reject so the input will not be added to the corpus.
    else:
      # Unexpected exceptions might be a bug in the source or in our test.
      raise e  # Alert a human to take a closer look at what caused this.


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
