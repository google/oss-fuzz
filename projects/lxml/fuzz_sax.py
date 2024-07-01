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
from test_utils import is_expected_error

with atheris.instrument_imports():
  from lxml import sax, etree


def TestOneInput(data):
  try:
    f = io.BytesIO(data)
    parsed = etree.parse(f)

    handler = sax.ElementTreeContentHandler()
    sax.ElementTreeProducer(parsed, handler).saxify()
  except (etree.LxmlError, etree.LxmlSyntaxError):
    return -1  # Reject so the input will not be added to the corpus.
  except (ValueError, IndexError, AttributeError) as e:
    if "lxml.sax.ElementTreeContentHandler.processingInstruction" in str(e):
      # This possibility is a bug and tracked here: https://bugs.launchpad.net/lxml/+bug/2011542
      return 0  # Accept the input in the corpus to enable regression testing when fixed.
    elif is_expected_error(["Invalid", "has no attribute"], e):
      return -1
    else:
      raise e


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
