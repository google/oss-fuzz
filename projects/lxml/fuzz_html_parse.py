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
from test_utils import is_expected_error

with atheris.instrument_imports():
  from lxml import etree


def TestOneInput(data):
  try:
    root = etree.HTML(data)
    etree.tostring(root)
  except (etree.LxmlError, TypeError, ValueError) as e:
    expected_error_message_content = [
        "C14N",
        "serialisation",
        "cannot be serialized",
        "unicode must not",
    ]
    if isinstance(e, etree.LxmlError) or (
        isinstance(e, (TypeError, ValueError)) and
        is_expected_error(expected_error_message_content, e)):
      # Known exception raised by the source code are not interesting.
      return -1  # Reject so the input will not be added to the corpus.
    else:
      # Unexpected exceptions might be a bug in the source or in our test.
      raise e  # Alert a human to take a closer look at what caused this.


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
